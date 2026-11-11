//! Experimental RISC-V V kernel (feature `experimental-riscv-rvv`).
//!
//! The leaf kernel is stable Rust naked assembly: only its local assembler
//! option enables V, so the rest of the binary remains RV64GC. It scans the
//! fixed segment snapshot in length-agnostic chunks; no assumptions are made
//! about VLEN. This is not measured and is never selected by default.

use crate::arch::KernelSet;
use crate::core::{AgeKernel, PAGES_PER_SEGMENT, aged_pages};

/// Return the guarded V wrapper when dispatch policy and hardware select RVV.
/// The wrapper rechecks policy and the calling thread's permission on every
/// execution, so a stored pointer remains safe when moved between threads.
pub(super) fn age_kernel() -> Option<AgeKernel> {
  match super::selected_kernel_set() {
    KernelSet::Rvv => Some(aged_pages_rvv),
    _ => None,
  }
}

/// [`aged_pages`] using the V leaf when policy and this thread permit it.
fn aged_pages_rvv(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  if super::kernel_set() != KernelSet::Rvv {
    return aged_pages(since, cutoff);
  }

  // SAFETY: the wrapper rechecks the current dispatch policy and this
  // thread's Linux vector permission immediately before entering the leaf.
  // The leaf reads exactly 64 u64 values from this fixed-size shared borrow,
  // uses only caller-saved registers, and returns using the C ABI.
  #[expect(unsafe_code, reason = "calling the RVV naked assembly leaf")]
  unsafe {
    aged_pages_rvv_body(since.as_ptr(), cutoff)
  }
}

/// Length-agnostic leaf: compute the mask of `since[i] <= cutoff` for i < 64.
///
/// The V instructions are bracketed by an assembler-local ISA option. `vsetvli`
/// chooses the actual strip width from the implementation's VLEN and the
/// remaining element count. The 16-byte stack slot is ABI-aligned; clearing
/// its low eight bytes initializes bytes not stored by `vsm.v`. The explicit
/// low-VL mask removes inactive bits, including tail-agnostic bits in the final
/// stored byte. `processed` is always 0..63, so the scalar
/// shift is defined. Only caller-saved integer and vector registers are used.
#[unsafe(naked)]
unsafe extern "C" fn aged_pages_rvv_body(since: *const u64, cutoff: u64) -> u64 {
  core::arch::naked_asm!(
    ".option push",
    ".option arch, +v",
    "addi sp, sp, -16",
    "li a2, 64",
    "li a3, 0",
    "li a4, 0",
    "2:",
    "vsetvli t0, a2, e64, m8, ta, ma",
    "vle64.v v8, (a0)",
    "vmsleu.vx v0, v8, a1",
    "sd zero, 0(sp)",
    "vsm.v v0, (sp)",
    "ld t1, 0(sp)",
    "li t2, 64",
    "beq t0, t2, 3f",
    "li t2, 1",
    "sll t2, t2, t0",
    "addi t2, t2, -1",
    "and t1, t1, t2",
    "3:",
    "sll t1, t1, a3",
    "or a4, a4, t1",
    "slli t1, t0, 3",
    "add a0, a0, t1",
    "sub a2, a2, t0",
    "add a3, a3, t0",
    "bnez a2, 2b",
    "mv a0, a4",
    "addi sp, sp, 16",
    "ret",
    ".option pop",
  )
}

#[cfg(test)]
mod tests {
  use std::io;
  use std::os::unix::process::CommandExt;
  use std::process::Command;
  use std::sync::mpsc;

  use crate::arch::riscv64::vector_permission;
  use crate::arch::{FeaturePolicy, KernelSet};
  use crate::core::{AgeKernel, PAGES_PER_SEGMENT, aged_pages};
  use crate::policy::Policy;

  const CROSS_THREAD_CHILD: &str = "ALLOCATBELT_RVV_CROSS_THREAD_CHILD";
  const REQUIRE_VECTOR_CONTROL: &str = "ALLOCATBELT_REQUIRE_VECTOR_CONTROL";
  const PR_RISCV_V_SET_CONTROL: libc::c_int = 69;
  const PR_RISCV_V_VSTATE_CTRL_ON: libc::c_ulong = 2;
  const PR_RISCV_V_VSTATE_CTRL_OFF_NEXT: libc::c_ulong = 1 << 2;

  static TEST_ALLOCATOR: crate::global::Allocatbelt = crate::global::Allocatbelt;

  fn set_isa_policy(experimental_isa: FeaturePolicy) {
    let mut policy = Policy::DEFAULT;
    policy.experimental_isa = experimental_isa;
    TEST_ALLOCATOR.configure(policy).unwrap();
  }

  #[test]
  fn rvv_kernel_matches_the_portable_loop() {
    let direct_test = std::env::var_os("ALLOCATBELT_RVV_DIRECT_TEST").is_some();
    if vector_permission().is_err() && !direct_test {
      eprintln!("V not enabled for this thread: nothing to check");
      return;
    }
    crate::arch::kernel_tests::check("rvv", direct_leaf);
    for index in 0..crate::core::PAGES_PER_SEGMENT {
      let mut since = [u64::MAX; crate::core::PAGES_PER_SEGMENT];
      since[index] = 0;
      assert_eq!(direct_leaf(&since, 0), 1u64 << index, "index {index}");
    }
  }

  #[test]
  fn rvv_leaf_reads_exactly_one_snapshot_at_a_guard_boundary() {
    let direct_test = std::env::var_os("ALLOCATBELT_RVV_DIRECT_TEST").is_some();
    if vector_permission().is_err() && !direct_test {
      eprintln!("V not enabled for this thread: nothing to check");
      return;
    }

    const ARENA: usize = 64 * 1024;
    const SNAPSHOT_BYTES: usize = crate::core::PAGES_PER_SEGMENT * core::mem::size_of::<u64>();
    let length = ARENA * 2;
    // SAFETY: anonymous private mapping with a null hint reserves a fresh
    // region; `Mapped` keeps it alive for the rest of this test.
    let base = unsafe {
      libc::mmap(
        core::ptr::null_mut(),
        length,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
      )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let mapping = Mapped {
      base: base.cast(),
      length,
    };
    // SAFETY: the second 64 KiB is inside this fresh mapping and begins on
    // a system-page boundary; no Rust reference points into that half.
    let protected = unsafe {
      libc::mprotect(
        mapping.base.wrapping_add(ARENA).cast(),
        ARENA,
        libc::PROT_NONE,
      )
    };
    assert_eq!(protected, 0);

    let snapshot = mapping
      .base
      .wrapping_add(ARENA - SNAPSHOT_BYTES)
      .cast::<u64>();
    for index in 0..crate::core::PAGES_PER_SEGMENT {
      let slot = snapshot.wrapping_add(index);
      // SAFETY: this writes one initialized u64 inside the readable half of
      // the mapping; the 64 slots exactly end at its guard-page boundary.
      unsafe { slot.write(index as u64) };
    }
    // SAFETY: the whole first half is this test's private mapping. Every
    // value is initialized and the leaf will only read the snapshot there.
    let protected_read_only =
      unsafe { libc::mprotect(mapping.base.cast(), ARENA, libc::PROT_READ) };
    assert_eq!(protected_read_only, 0);
    // SAFETY: all elements are initialized, correctly aligned, and the
    // fixed-size array extent stops exactly before the PROT_NONE half.
    let snapshot = unsafe { &*snapshot.cast::<[u64; crate::core::PAGES_PER_SEGMENT]>() };
    assert_eq!(direct_leaf(snapshot, u64::MAX), u64::MAX);
  }

  #[test]
  fn a_saved_age_kernel_rechecks_the_calling_threads_permission() {
    if std::env::var_os(CROSS_THREAD_CHILD).is_some() {
      saved_kernel_in_off_parent_and_on_worker();
      return;
    }
    if vector_permission().is_err() {
      assert!(
        std::env::var_os(REQUIRE_VECTOR_CONTROL).is_none(),
        "this check requires a working vector-control interface"
      );
      eprintln!("thread-local RVV permission unavailable: saved-kernel test skipped");
      return;
    }

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
      .args([
        "--exact",
        "arch::rvv::tests::a_saved_age_kernel_rechecks_the_calling_threads_permission",
        "--nocapture",
      ])
      .env(CROSS_THREAD_CHILD, "1");
    // SAFETY: this pre-exec hook makes one allocation-free prctl call to set
    // the next exec's vector state OFF; it neither accesses allocator state
    // nor touches parent-thread state.
    unsafe {
      command.pre_exec(set_off_for_next_exec);
    }
    assert!(
      command.status().unwrap().success(),
      "OFF-thread child failed"
    );
  }

  fn set_off_for_next_exec() -> io::Result<()> {
    // SAFETY: SET_CONTROL takes a scalar control word and no pointer.
    let result = unsafe {
      libc::prctl(
        PR_RISCV_V_SET_CONTROL,
        PR_RISCV_V_VSTATE_CTRL_OFF_NEXT,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
      )
    };
    if result < 0 {
      Err(io::Error::last_os_error())
    } else {
      Ok(())
    }
  }

  fn saved_kernel_in_off_parent_and_on_worker() {
    assert!(vector_permission().is_err(), "child must start with V OFF");
    let mut since = [u64::MAX; PAGES_PER_SEGMENT];
    since[0] = 0;
    since[17] = 0;
    since[63] = 0;
    let expected = aged_pages(&since, 0);

    let (kernel_tx, kernel_rx) = mpsc::sync_channel::<AgeKernel>(0);
    let (policy_tx, policy_rx) = mpsc::sync_channel::<FeaturePolicy>(0);
    let (result_tx, result_rx) = mpsc::sync_channel::<(KernelSet, bool)>(0);
    std::thread::scope(|scope| {
      let worker = scope.spawn(|| {
        set_vector_control(PR_RISCV_V_VSTATE_CTRL_ON);
        crate::arch::initialize_dispatch();
        set_isa_policy(FeaturePolicy::Prefer);
        let kernel = crate::arch::age_kernel().expect("ON worker must select RVV");
        assert_eq!(kernel(&since, 0), expected, "ON worker must execute RVV");
        kernel_tx.send(kernel).unwrap();
        for policy in policy_rx {
          set_isa_policy(policy);
          let selected = crate::arch::kernel_set();
          result_tx
            .send((selected, kernel(&since, 0) == expected))
            .unwrap();
        }
      });

      let kernel = kernel_rx.recv().unwrap();
      assert_eq!(crate::arch::kernel_set(), KernelSet::Baseline);
      assert_eq!(kernel(&since, 0), expected, "OFF parent must take fallback");

      policy_tx.send(FeaturePolicy::Disable).unwrap();
      let (selected, correct) = result_rx.recv().unwrap();
      assert_eq!(selected, KernelSet::Baseline);
      assert!(correct);
      assert_eq!(kernel(&since, 0), expected);

      policy_tx.send(FeaturePolicy::Prefer).unwrap();
      let (selected, correct) = result_rx.recv().unwrap();
      assert_eq!(selected, KernelSet::Rvv);
      assert!(correct, "ON worker must still call the saved RVV kernel");
      assert_eq!(crate::arch::kernel_set(), KernelSet::Baseline);
      assert_eq!(
        kernel(&since, 0),
        expected,
        "saved pointer must recheck OFF parent"
      );

      drop(policy_tx);
      worker.join().unwrap();
    });
  }

  fn set_vector_control(control: libc::c_ulong) {
    // SAFETY: SET_CONTROL changes only this worker thread's vector state;
    // this scalar control word contains no pointer.
    let result = unsafe {
      libc::prctl(
        PR_RISCV_V_SET_CONTROL,
        control,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
      )
    };
    assert_eq!(
      result,
      0,
      "SET_CONTROL failed: {:?}",
      io::Error::last_os_error()
    );
  }

  struct Mapped {
    base: *mut u8,
    length: usize,
  }

  impl Drop for Mapped {
    fn drop(&mut self) {
      // SAFETY: this test-owned mapping has not been unmapped elsewhere.
      assert_eq!(unsafe { libc::munmap(self.base.cast(), self.length) }, 0);
    }
  }

  /// Deliberately bypasses policy dispatch to test the instruction body.
  fn direct_leaf(since: &[u64; crate::core::PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
    // SAFETY: the test checks this calling thread's V permission, or is run
    // with the explicit controlled-QEMU override on a V-enabled CPU; the
    // leaf only reads `since`.
    unsafe { super::aged_pages_rvv_body(since.as_ptr(), cutoff) }
  }
}
