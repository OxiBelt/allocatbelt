//! Admission accounting: the outstanding-job bound and the reserved
//! resource vector. Plain data, kept under the scheduler lock.

use crate::error::SubmitErrorKind;
use crate::resources::Resources;

/// What the runtime has admitted and not yet released.
///
/// Invariants: `outstanding <= max_outstanding` and `reserved` fits within
/// `capacity`, so every sum is checked against `capacity` before it is
/// stored and no subtraction can underflow while each admission is
/// released at most once.
#[derive(Debug)]
pub(crate) struct Admission {
  max_outstanding: usize,
  capacity: Resources,
  outstanding: usize,
  reserved: Resources,
}

impl Admission {
  pub(crate) const fn new(max_outstanding: usize, capacity: Resources) -> Self {
    Self {
      max_outstanding,
      capacity,
      outstanding: 0,
      reserved: Resources::ZERO,
    }
  }

  /// Reserves `request` and one outstanding slot, or says why not.
  ///
  /// A request larger than the capacity in any component can never be
  /// admitted (`InvalidRequest`); otherwise a full outstanding bound is
  /// `Full` and a request that does not fit what is free now is
  /// `InsufficientResources`. A zero request takes only a slot.
  pub(crate) fn try_admit(&mut self, request: &Resources) -> Result<(), SubmitErrorKind> {
    if !request.fits_within(&self.capacity) {
      return Err(SubmitErrorKind::InvalidRequest);
    }
    if self.outstanding >= self.max_outstanding {
      return Err(SubmitErrorKind::Full);
    }
    // `reserved` fits within `capacity`, so `free` exists; the sum then
    // fits within `capacity` too and cannot overflow.
    let free = self
      .capacity
      .checked_sub(&self.reserved)
      .ok_or(SubmitErrorKind::InsufficientResources)?;
    if !request.fits_within(&free) {
      return Err(SubmitErrorKind::InsufficientResources);
    }
    let reserved = self
      .reserved
      .checked_add(request)
      .ok_or(SubmitErrorKind::InsufficientResources)?;
    self.reserved = reserved;
    self.outstanding += 1;
    Ok(())
  }

  /// Returns one admission of `request`. `false`, leaving the counts
  /// unchanged, when nothing matching was admitted (a release without an
  /// admission is a bug the debug assertion reports).
  pub(crate) fn release(&mut self, request: &Resources) -> bool {
    let (Some(outstanding), Some(reserved)) = (
      self.outstanding.checked_sub(1),
      self.reserved.checked_sub(request),
    ) else {
      debug_assert!(false, "release without a matching admission");
      return false;
    };
    self.outstanding = outstanding;
    self.reserved = reserved;
    true
  }

  pub(crate) const fn outstanding(&self) -> usize {
    self.outstanding
  }

  pub(crate) const fn reserved(&self) -> Resources {
    self.reserved
  }
}

#[cfg(test)]
mod tests {
  use super::Admission;
  use crate::error::SubmitErrorKind;
  use crate::resources::Resources;

  const MAX: Resources = Resources {
    cpu: usize::MAX,
    memory: usize::MAX,
    disk: usize::MAX,
    network: usize::MAX,
  };

  fn cpu(n: usize) -> Resources {
    Resources {
      cpu: n,
      ..Resources::ZERO
    }
  }

  #[test]
  fn usize_max_capacity_admits_exactly_up_to_the_boundary() {
    let mut a = Admission::new(usize::MAX, MAX);
    assert_eq!(a.try_admit(&MAX), Ok(()));
    assert_eq!(a.reserved(), MAX);
    // Anything more would overflow: refused, not wrapped.
    assert_eq!(
      a.try_admit(&cpu(1)),
      Err(SubmitErrorKind::InsufficientResources)
    );
    assert_eq!(a.try_admit(&Resources::ZERO), Ok(()));
    assert_eq!(a.outstanding(), 2);
    assert!(a.release(&Resources::ZERO));
    assert!(a.release(&MAX));
    assert_eq!(a.reserved(), Resources::ZERO);
    assert_eq!(a.outstanding(), 0);
  }

  #[test]
  fn split_reservations_meet_at_usize_max() {
    let mut a = Admission::new(4, MAX);
    let half = cpu(usize::MAX / 2);
    assert_eq!(a.try_admit(&half), Ok(()));
    assert_eq!(a.try_admit(&half), Ok(()));
    assert_eq!(a.try_admit(&cpu(1)), Ok(()));
    assert_eq!(a.reserved().cpu, usize::MAX);
    assert_eq!(
      a.try_admit(&cpu(1)),
      Err(SubmitErrorKind::InsufficientResources)
    );
  }

  #[test]
  fn error_kinds_in_order() {
    let mut a = Admission::new(1, cpu(4));
    assert_eq!(a.try_admit(&cpu(5)), Err(SubmitErrorKind::InvalidRequest));
    let mut big = Resources::ZERO;
    big.network = 1;
    assert_eq!(a.try_admit(&big), Err(SubmitErrorKind::InvalidRequest));
    assert_eq!(a.try_admit(&cpu(4)), Ok(()));
    // The bound is checked before the free resources.
    assert_eq!(a.try_admit(&cpu(1)), Err(SubmitErrorKind::Full));
    assert_eq!(a.try_admit(&cpu(5)), Err(SubmitErrorKind::InvalidRequest));
    assert!(a.release(&cpu(4)));
    let mut b = Admission::new(2, cpu(4));
    assert_eq!(b.try_admit(&cpu(3)), Ok(()));
    assert_eq!(
      b.try_admit(&cpu(2)),
      Err(SubmitErrorKind::InsufficientResources)
    );
    assert_eq!(b.try_admit(&cpu(1)), Ok(()));
  }

  #[test]
  fn zero_requests_are_bounded_by_outstanding() {
    let mut a = Admission::new(3, Resources::ZERO);
    for _ in 0..3 {
      assert_eq!(a.try_admit(&Resources::ZERO), Ok(()));
    }
    assert_eq!(a.try_admit(&Resources::ZERO), Err(SubmitErrorKind::Full));
    assert_eq!(a.try_admit(&cpu(1)), Err(SubmitErrorKind::InvalidRequest));
  }

  #[test]
  fn rejections_leave_counts_unchanged() {
    let mut a = Admission::new(2, cpu(2));
    assert_eq!(a.try_admit(&cpu(2)), Ok(()));
    for r in [cpu(1), cpu(3), cpu(usize::MAX)] {
      assert!(a.try_admit(&r).is_err());
      assert_eq!((a.outstanding(), a.reserved()), (1, cpu(2)));
    }
  }

  #[test]
  #[cfg_attr(debug_assertions, should_panic(expected = "release without"))]
  fn unmatched_release_changes_nothing() {
    let mut a = Admission::new(2, cpu(2));
    assert_eq!(a.try_admit(&cpu(1)), Ok(()));
    assert!(!a.release(&cpu(2)));
    assert_eq!((a.outstanding(), a.reserved()), (1, cpu(1)));
  }
}
