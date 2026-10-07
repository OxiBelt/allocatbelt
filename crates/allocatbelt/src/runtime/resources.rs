//! The resource vector jobs declare and the runtime reserves.

/// Declared concurrent resource units of a job, or the capacity of a
/// runtime.
///
/// These are accounting units the caller chooses (CPU slots, bytes of
/// working allocations, disk or network units). They are reserved in full
/// at submission and returned when the job ends. The runtime does not
/// measure or enforce them: they are not CPU quotas, RSS limits, bandwidth
/// or rate limits or disk-space limits. A job that allocates more than it
/// declared is not stopped, and a result kept after the job ends is not
/// counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Resources {
  /// CPU units.
  pub cpu: usize,
  /// Memory units, such as bytes.
  pub memory: usize,
  /// Disk units.
  pub disk: usize,
  /// Network units.
  pub network: usize,
}

impl Resources {
  /// No resources.
  pub const ZERO: Self = Self {
    cpu: 0,
    memory: 0,
    disk: 0,
    network: 0,
  };

  /// Whether every component is at most the matching one of `other`.
  #[must_use]
  pub const fn fits_within(&self, other: &Self) -> bool {
    self.cpu <= other.cpu
      && self.memory <= other.memory
      && self.disk <= other.disk
      && self.network <= other.network
  }

  /// Component-wise sum, `None` when a component overflows.
  #[must_use]
  pub const fn checked_add(&self, other: &Self) -> Option<Self> {
    let (Some(cpu), Some(memory), Some(disk), Some(network)) = (
      self.cpu.checked_add(other.cpu),
      self.memory.checked_add(other.memory),
      self.disk.checked_add(other.disk),
      self.network.checked_add(other.network),
    ) else {
      return None;
    };
    Some(Self {
      cpu,
      memory,
      disk,
      network,
    })
  }

  /// Component-wise difference, `None` when a component would go below zero.
  #[must_use]
  pub const fn checked_sub(&self, other: &Self) -> Option<Self> {
    let (Some(cpu), Some(memory), Some(disk), Some(network)) = (
      self.cpu.checked_sub(other.cpu),
      self.memory.checked_sub(other.memory),
      self.disk.checked_sub(other.disk),
      self.network.checked_sub(other.network),
    ) else {
      return None;
    };
    Some(Self {
      cpu,
      memory,
      disk,
      network,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::Resources;

  const MAX: Resources = Resources {
    cpu: usize::MAX,
    memory: usize::MAX,
    disk: usize::MAX,
    network: usize::MAX,
  };

  fn one(i: usize) -> Resources {
    let mut r = Resources::ZERO;
    match i {
      0 => r.cpu = 1,
      1 => r.memory = 1,
      2 => r.disk = 1,
      _ => r.network = 1,
    }
    r
  }

  #[test]
  fn each_component_overflows_and_underflows_alone() {
    for i in 0..4 {
      assert_eq!(MAX.checked_add(&one(i)), None);
      assert_eq!(Resources::ZERO.checked_sub(&one(i)), None);
      assert!(!one(i).fits_within(&Resources::ZERO));
      assert!(one(i).fits_within(&one(i)));
      assert_eq!(one(i).checked_sub(&one(i)), Some(Resources::ZERO));
      assert_eq!(Resources::ZERO.checked_add(&one(i)), Some(one(i)));
    }
    assert_eq!(MAX.checked_add(&Resources::ZERO), Some(MAX));
    assert_eq!(MAX.checked_sub(&MAX), Some(Resources::ZERO));
    assert!(Resources::ZERO.fits_within(&Resources::ZERO));
    assert!(MAX.fits_within(&MAX));
  }
}
