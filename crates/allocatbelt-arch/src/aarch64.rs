//! aarch64 detection from the auxiliary vector (`AT_HWCAP`, `AT_HWCAP2`).
//!
//! `getauxval(3)` reads the vector libc saved at start-up: no syscall, no
//! allocation, no file I/O (glibc and musl). The bits are from Linux
//! `arch/arm64/include/uapi/asm/hwcap.h` (checked against v7.0); the `libc`
//! crate lacks `HWCAP2_SVE2` for glibc.

use crate::CpuFeatures;

const HWCAP_ASIMD: libc::c_ulong = 1 << 1;
const HWCAP_SVE: libc::c_ulong = 1 << 22;
const HWCAP2_SVE2: libc::c_ulong = 1 << 1;

pub(crate) fn detect() -> CpuFeatures {
  // SAFETY: `getauxval` takes any key and returns 0 for unknown ones; it
  // only reads libc's saved copy of the auxiliary vector.
  #[expect(unsafe_code, reason = "getauxval FFI call")]
  let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
  // SAFETY: as above.
  #[expect(unsafe_code, reason = "getauxval FFI call")]
  let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
  CpuFeatures::empty()
    .with_if(CpuFeatures::ASIMD, hwcap & HWCAP_ASIMD != 0)
    .with_if(CpuFeatures::SVE, hwcap & HWCAP_SVE != 0)
    .with_if(CpuFeatures::SVE2, hwcap2 & HWCAP2_SVE2 != 0)
}

#[cfg(test)]
mod tests {
  use crate::CpuFeatures;

  #[test]
  fn matches_std_detection() {
    let f = super::detect();
    let pairs = [
      (
        CpuFeatures::ASIMD,
        std::arch::is_aarch64_feature_detected!("asimd"),
      ),
      (
        CpuFeatures::SVE,
        std::arch::is_aarch64_feature_detected!("sve"),
      ),
      (
        CpuFeatures::SVE2,
        std::arch::is_aarch64_feature_detected!("sve2"),
      ),
    ];
    for (feature, expected) in pairs {
      assert_eq!(
        f.contains(feature),
        expected,
        "{feature:?} (detected {f:?})"
      );
    }
  }
}
