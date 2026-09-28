//! riscv64 detection with the `riscv_hwprobe` syscall.
//!
//! Constants are from Linux `arch/riscv/include/uapi/asm/hwprobe.h`
//! (checked against v7.0) and `Documentation/arch/riscv/hwprobe.rst`; the
//! syscall number is `__NR_arch_specific_syscall + 14` from
//! `include/uapi/asm-generic/unistd.h`. Neither is in the `libc` crate yet.

use crate::arch::CpuFeatures;

const NR_RISCV_HWPROBE: libc::c_long = 244 + 14;
const RISCV_HWPROBE_KEY_IMA_EXT_0: i64 = 4;
const RISCV_HWPROBE_IMA_V: u64 = 1 << 2;
const RISCV_HWPROBE_EXT_ZBB: u64 = 1 << 4;

/// `struct riscv_hwprobe`.
#[repr(C)]
struct Pair {
  key: i64,
  value: u64,
}

pub(crate) fn detect() -> CpuFeatures {
  let mut pair = Pair {
    key: RISCV_HWPROBE_KEY_IMA_EXT_0,
    value: 0,
  };
  // SAFETY: `riscv_hwprobe(pairs, pair_count, cpusetsize, cpus, flags)`
  // writes only to the one `Pair` passed (a live, exclusive local with the
  // kernel's layout). A null CPU set of size 0 means "all online CPUs", so
  // a feature is reported only if every CPU has it, and flags must be 0.
  #[expect(unsafe_code, reason = "riscv_hwprobe syscall")]
  let r = unsafe {
    libc::syscall(
      NR_RISCV_HWPROBE,
      &raw mut pair,
      1usize,
      0usize,
      core::ptr::null_mut::<libc::c_void>(),
      0 as libc::c_uint,
    )
  };
  // Unknown keys come back as -1; an error (ENOSYS on a kernel without
  // hwprobe, which Linux 7.0 always has) leaves only the baseline.
  if r != 0 || pair.key != RISCV_HWPROBE_KEY_IMA_EXT_0 {
    return CpuFeatures::empty();
  }
  CpuFeatures::empty()
    .with_if(CpuFeatures::ZBB, pair.value & RISCV_HWPROBE_EXT_ZBB != 0)
    .with_if(CpuFeatures::RVV, pair.value & RISCV_HWPROBE_IMA_V != 0)
}

#[cfg(test)]
mod tests {
  use crate::arch::CpuFeatures;

  /// `is_riscv_feature_detected!` is unstable, so the check is the build:
  /// a `+zbb` build only runs where Zbb exists, and CI tests one under
  /// qemu-user.
  #[test]
  fn a_zbb_build_detects_zbb() {
    let f = super::detect();
    if cfg!(target_feature = "zbb") {
      assert!(f.contains(CpuFeatures::ZBB), "detected {f:?}");
    }
    assert!(!f.contains(CpuFeatures::AVX2));
    assert!(!f.contains(CpuFeatures::ASIMD));
  }
}
