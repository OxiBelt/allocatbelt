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

pub(crate) use vector_control::vector_permission;

/// Whether this thread may run the V instructions a riscv64 build contains:
/// the CPUs have V and the thread's vector state is not off. `Err` carries
/// the message to stop with. Allocation-free: two syscalls at most (the
/// hardware detection is cached by the caller).
#[inline(never)]
pub(crate) fn vector_ready(cpus_have_v: bool) -> Result<(), &'static str> {
  if !cpus_have_v {
    return verdict(false, Ok(()));
  }
  verdict(true, vector_permission())
}

/// The decision of [`vector_ready`] from its two inputs. A query the kernel
/// or an emulator refuses (qemu-user answers `EINVAL`) is not taken as off,
/// since Linux 7.0 always answers it; see docs/platform.md.
fn verdict(cpus_have_v: bool, permission: Result<(), i32>) -> Result<(), &'static str> {
  if !cpus_have_v {
    return Err(NO_V);
  }
  match permission {
    Err(0) => Err(V_OFF),
    Ok(()) | Err(_) => Ok(()),
  }
}

const NO_V: &str = "allocatbelt: this riscv64 build needs the V extension, and riscv_hwprobe reports no V on this machine's CPUs; see docs/platform.md";
const V_OFF: &str = "allocatbelt: this riscv64 build needs the V extension, and vector instructions are off for this thread (prctl PR_RISCV_V_GET_CONTROL, sysctl abi.riscv_v_default_allow); see docs/platform.md";

#[cfg(test)]
mod verdict_tests {
  use super::{NO_V, V_OFF, verdict};

  #[test]
  fn refuses_cpus_without_v_and_threads_with_v_off() {
    for permission in [Ok(()), Err(0), Err(libc::EINVAL)] {
      assert_eq!(verdict(false, permission), Err(NO_V));
    }
    assert_eq!(verdict(true, Err(0)), Err(V_OFF));
  }

  #[test]
  fn runs_with_v_on_or_an_unanswered_query() {
    assert_eq!(verdict(true, Ok(())), Ok(()));
    for errno in [libc::EINVAL, libc::ENOSYS, libc::EPERM] {
      assert_eq!(verdict(true, Err(errno)), Ok(()));
    }
  }
}

mod vector_control {
  /// Linux `include/uapi/linux/prctl.h` and
  /// `Documentation/arch/riscv/vector.rst`.
  const PR_RISCV_V_GET_CONTROL: libc::c_int = 70;
  const PR_RISCV_V_VSTATE_CTRL_CUR_MASK: libc::c_int = 0x3;
  const PR_RISCV_V_VSTATE_CTRL_ON: libc::c_int = 2;

  /// Checks execution permission on this thread, independently of cached
  /// hardware detection. Never enables V or caches a thread's permission.
  /// An explicit denial or unexpected current state returns `Err(0)`;
  /// a refused query returns its errno. Errors, including an emulator's
  /// `EINVAL`, are not evidence that vector instructions may execute.
  pub(crate) fn vector_permission() -> Result<(), i32> {
    // SAFETY: this option reads only the calling thread's control word;
    // the remaining unsigned-long arguments are zero and contain no pointer.
    #[expect(unsafe_code, reason = "reading this thread's vector control")]
    let control = unsafe {
      libc::prctl(
        PR_RISCV_V_GET_CONTROL,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
      )
    };
    let result = if control < 0 {
      Err(
        std::io::Error::last_os_error()
          .raw_os_error()
          .unwrap_or(libc::EIO),
      )
    } else {
      Ok(control)
    };
    interpret(result)
  }

  fn interpret(control: Result<libc::c_int, i32>) -> Result<(), i32> {
    match control {
      Ok(control)
        if control >= 0
          && control & PR_RISCV_V_VSTATE_CTRL_CUR_MASK == PR_RISCV_V_VSTATE_CTRL_ON =>
      {
        Ok(())
      }
      Ok(_) => Err(0),
      Err(errno) => Err(errno),
    }
  }

  #[cfg(test)]
  mod tests {
    use super::interpret;

    #[test]
    fn only_explicit_current_on_allows_vector_execution() {
      // DEFAULT, OFF and the reserved current-state value fail closed.
      for control in [-2, -1, 0, 1, 3] {
        assert_eq!(interpret(Ok(control)), Err(0));
      }
      assert_eq!(interpret(Ok(2)), Ok(()));
      // Next-exec and inheritance settings do not change current permission.
      for next in 0..=2 {
        for inherit in [0, 1 << 4] {
          assert_eq!(interpret(Ok(2 | (next << 2) | inherit)), Ok(()));
          assert_eq!(interpret(Ok(1 | (next << 2) | inherit)), Err(0));
        }
      }
    }

    #[test]
    fn failed_queries_preserve_the_error_and_never_allow_vectors() {
      for errno in [
        libc::EINVAL,
        libc::EPERM,
        libc::ENOSYS,
        libc::EACCES,
        libc::EIO,
      ] {
        assert_eq!(interpret(Err(errno)), Err(errno));
      }
    }
  }
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
