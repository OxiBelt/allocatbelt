//! x86_64 detection with `cpuid` and `xgetbv`.
//!
//! Bit positions are from the Intel SDM (vol. 2A, `CPUID`; vol. 1, §13.3 for
//! `XCR0`), and the tests check the result against `std`'s
//! `is_x86_feature_detected!`.

use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};

use crate::CpuFeatures;

const fn bit(reg: u32, n: u32) -> bool {
  reg & (1 << n) != 0
}

/// `XCR0` bits the OS sets when it saves the state an extension needs.
const XCR0_SSE_AVX: u64 = 0b110; // XMM, YMM
const XCR0_AVX512: u64 = 0b1110_0000; // opmask, ZMM_Hi256, Hi16_ZMM

pub(crate) fn detect() -> CpuFeatures {
  let max_leaf = __cpuid(0).eax;
  let leaf1 = __cpuid(1);
  let leaf7 = if max_leaf >= 7 {
    __cpuid_count(7, 0)
  } else {
    CpuidResult {
      eax: 0,
      ebx: 0,
      ecx: 0,
      edx: 0,
    }
  };
  let ext1_ecx = if __cpuid(0x8000_0000).eax >= 0x8000_0001 {
    __cpuid(0x8000_0001).ecx
  } else {
    0
  };
  let xcr0 = if bit(leaf1.ecx, 27) { xcr0() } else { 0 };
  let os_avx = xcr0 & XCR0_SSE_AVX == XCR0_SSE_AVX;
  let os_avx512 = os_avx && xcr0 & XCR0_AVX512 == XCR0_AVX512;

  let v2 = bit(leaf1.ecx, 0) // SSE3
    && bit(leaf1.ecx, 9) // SSSE3
    && bit(leaf1.ecx, 13) // CMPXCHG16B
    && bit(leaf1.ecx, 19) // SSE4.1
    && bit(leaf1.ecx, 20) // SSE4.2
    && bit(leaf1.ecx, 23); // POPCNT
  let avx = os_avx && bit(leaf1.ecx, 28);
  let avx2 = avx && bit(leaf7.ebx, 5);
  let v3 = v2
    && avx2
    && bit(leaf1.ecx, 12) // FMA
    && bit(leaf1.ecx, 22) // MOVBE
    && bit(leaf1.ecx, 26) // XSAVE
    && bit(leaf1.ecx, 29) // F16C
    && bit(leaf7.ebx, 3) // BMI1
    && bit(leaf7.ebx, 8) // BMI2
    && bit(ext1_ecx, 5); // LZCNT
  let avx512f = os_avx512 && bit(leaf7.ebx, 16);

  CpuFeatures::empty()
    .with_if(CpuFeatures::X86_64_V3, v3)
    .with_if(CpuFeatures::AVX2, avx2)
    .with_if(CpuFeatures::AVX512F, avx512f)
    .with_if(CpuFeatures::AVX512DQ, avx512f && bit(leaf7.ebx, 17))
    .with_if(CpuFeatures::AVX512CD, avx512f && bit(leaf7.ebx, 28))
    .with_if(CpuFeatures::AVX512BW, avx512f && bit(leaf7.ebx, 30))
    .with_if(CpuFeatures::AVX512VL, avx512f && bit(leaf7.ebx, 31))
    .with_if(CpuFeatures::AVX512VPOPCNTDQ, avx512f && bit(leaf7.ecx, 14))
}

/// `XCR0`; only called when `CPUID.1:ECX.OSXSAVE` is set.
#[cfg(target_feature = "xsave")]
fn xcr0() -> u64 {
  // SAFETY: `xgetbv` faults unless the OS enabled XSAVE, which the caller
  // checked (`CPUID.1:ECX.OSXSAVE`); the `xsave` target feature is enabled
  // for the whole build (x86-64-v3), and register 0 always exists.
  #[expect(unsafe_code, reason = "xgetbv instruction")]
  unsafe {
    core::arch::x86_64::_xgetbv(0)
  }
}

/// Builds below x86-64-v3 are rejected by `allocatbelt-sys`; without the
/// `xsave` target feature report no OS-enabled vector state.
#[cfg(not(target_feature = "xsave"))]
fn xcr0() -> u64 {
  0
}

#[cfg(test)]
mod tests {
  use crate::CpuFeatures;

  #[test]
  fn matches_std_detection() {
    let f = super::detect();
    let pairs = [
      (
        CpuFeatures::AVX2,
        std::arch::is_x86_feature_detected!("avx2"),
      ),
      (
        CpuFeatures::AVX512F,
        std::arch::is_x86_feature_detected!("avx512f"),
      ),
      (
        CpuFeatures::AVX512CD,
        std::arch::is_x86_feature_detected!("avx512cd"),
      ),
      (
        CpuFeatures::AVX512BW,
        std::arch::is_x86_feature_detected!("avx512bw"),
      ),
      (
        CpuFeatures::AVX512DQ,
        std::arch::is_x86_feature_detected!("avx512dq"),
      ),
      (
        CpuFeatures::AVX512VL,
        std::arch::is_x86_feature_detected!("avx512vl"),
      ),
      (
        CpuFeatures::AVX512VPOPCNTDQ,
        std::arch::is_x86_feature_detected!("avx512vpopcntdq"),
      ),
    ];
    for (feature, expected) in pairs {
      assert_eq!(
        f.contains(feature),
        expected,
        "{feature:?} (detected {f:?})"
      );
    }
    let v3 = [
      "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe", "xsave",
    ]
    .iter()
    .chain(&["cmpxchg16b", "popcnt", "sse3", "ssse3", "sse4.1", "sse4.2"])
    .all(|name| std_detected(name));
    assert_eq!(f.contains(CpuFeatures::X86_64_V3), v3, "detected {f:?}");
  }

  #[test]
  fn a_v3_build_runs_on_a_v3_cpu() {
    assert!(super::detect().contains(CpuFeatures::X86_64_V3 | CpuFeatures::AVX2));
  }

  fn std_detected(name: &str) -> bool {
    match name {
      "avx" => std::arch::is_x86_feature_detected!("avx"),
      "avx2" => std::arch::is_x86_feature_detected!("avx2"),
      "bmi1" => std::arch::is_x86_feature_detected!("bmi1"),
      "bmi2" => std::arch::is_x86_feature_detected!("bmi2"),
      "f16c" => std::arch::is_x86_feature_detected!("f16c"),
      "fma" => std::arch::is_x86_feature_detected!("fma"),
      "lzcnt" => std::arch::is_x86_feature_detected!("lzcnt"),
      "movbe" => std::arch::is_x86_feature_detected!("movbe"),
      "xsave" => std::arch::is_x86_feature_detected!("xsave"),
      "cmpxchg16b" => std::arch::is_x86_feature_detected!("cmpxchg16b"),
      "popcnt" => std::arch::is_x86_feature_detected!("popcnt"),
      "sse3" => std::arch::is_x86_feature_detected!("sse3"),
      "ssse3" => std::arch::is_x86_feature_detected!("ssse3"),
      "sse4.1" => std::arch::is_x86_feature_detected!("sse4.1"),
      "sse4.2" => std::arch::is_x86_feature_detected!("sse4.2"),
      _ => unreachable!("{name}"),
    }
  }
}
