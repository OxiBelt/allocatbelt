//! The compact feature set that detection produces.

use core::{fmt, ops};

/// ISA extensions the running CPU and kernel support, as a bitset.
///
/// Only features that some allocator kernel may use are tracked. Features of
/// other architectures are never set.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CpuFeatures(u32);

macro_rules! features {
  ($($(#[$doc:meta])* $name:ident = $bit:expr, $label:literal;)*) => {
    impl CpuFeatures {
      $($(#[$doc])* pub const $name: Self = Self(1 << $bit);)*

      /// Every tracked feature, with its name, for `Debug` and diagnostics.
      pub const ALL: &[(Self, &str)] = &[$((Self::$name, $label)),*];
    }
  };
}

features! {
  /// x86_64: the whole x86-64-v3 feature set (AVX, AVX2, BMI1, BMI2, F16C,
  /// FMA, LZCNT, MOVBE, XSAVE and the v2 set), with AVX state enabled by
  /// the OS.
  X86_64_V3 = 0, "x86-64-v3";
  /// x86_64: AVX2, with AVX state enabled by the OS.
  AVX2 = 1, "avx2";
  /// x86_64: AVX-512 Foundation, with opmask and ZMM state enabled by the OS.
  AVX512F = 2, "avx512f";
  /// x86_64: AVX-512 Conflict Detection (with `AVX512F`).
  AVX512CD = 3, "avx512cd";
  /// x86_64: AVX-512 Byte and Word (with `AVX512F`).
  AVX512BW = 4, "avx512bw";
  /// x86_64: AVX-512 Doubleword and Quadword (with `AVX512F`).
  AVX512DQ = 5, "avx512dq";
  /// x86_64: AVX-512 Vector Length extensions (with `AVX512F`).
  AVX512VL = 6, "avx512vl";
  /// x86_64: AVX-512 `VPOPCNTD`/`VPOPCNTQ` (with `AVX512F`).
  AVX512VPOPCNTDQ = 7, "avx512vpopcntdq";
  /// aarch64: Advanced SIMD (NEON).
  ASIMD = 8, "asimd";
  /// aarch64: the Scalable Vector Extension.
  SVE = 9, "sve";
  /// aarch64: SVE2.
  SVE2 = 10, "sve2";
  /// riscv64: the Zbb basic bit-manipulation extension.
  ZBB = 11, "zbb";
  /// riscv64: the V vector extension.
  RVV = 12, "v";
}

impl CpuFeatures {
  const MASK: u32 = (1 << 13) - 1;

  /// No features.
  #[must_use]
  pub const fn empty() -> Self {
    Self(0)
  }

  /// The raw bits.
  #[must_use]
  pub const fn bits(self) -> u32 {
    self.0
  }

  /// The features in `bits`, ignoring bits that name no feature.
  #[must_use]
  pub const fn from_bits(bits: u32) -> Self {
    Self(bits & Self::MASK)
  }

  /// Whether every feature in `other` is present.
  #[must_use]
  pub const fn contains(self, other: Self) -> bool {
    self.0 & other.0 == other.0
  }

  /// `self` with `other` added when `present`.
  #[must_use]
  pub const fn with_if(self, other: Self, present: bool) -> Self {
    if present {
      Self(self.0 | other.0)
    } else {
      self
    }
  }
}

impl ops::BitOr for CpuFeatures {
  type Output = Self;

  fn bitor(self, rhs: Self) -> Self {
    Self(self.0 | rhs.0)
  }
}

impl fmt::Debug for CpuFeatures {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let present = Self::ALL
      .iter()
      .filter(|(feature, _)| self.contains(*feature));
    f.debug_set()
      .entries(present.map(|(_, name)| name))
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::CpuFeatures;

  #[test]
  fn bits_are_distinct_and_masked() {
    let mut all = 0;
    for (feature, _) in CpuFeatures::ALL {
      assert_eq!(feature.bits().count_ones(), 1);
      assert_eq!(all & feature.bits(), 0);
      all |= feature.bits();
    }
    assert_eq!(CpuFeatures::from_bits(u32::MAX).bits(), all);
  }

  #[test]
  fn set_operations() {
    let f = CpuFeatures::empty()
      .with_if(CpuFeatures::AVX2, true)
      .with_if(CpuFeatures::SVE, false);
    assert!(f.contains(CpuFeatures::AVX2));
    assert!(!f.contains(CpuFeatures::SVE));
    assert!(f.contains(CpuFeatures::empty()));
    assert_eq!(std::format!("{f:?}"), "{\"avx2\"}");
  }
}
