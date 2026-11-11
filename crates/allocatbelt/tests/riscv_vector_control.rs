//! RISC-V vector permission is local to a thread, not a cached CPU feature.
//! Public dispatch fails closed when a sandbox refuses the control query.
//! Where Linux supports the interface, a fresh OFF process enables just one
//! thread and checks selection and policy validation on both threads.

#![cfg(all(target_arch = "riscv64", feature = "experimental-riscv-rvv"))]
#![expect(
  unsafe_code,
  reason = "isolated test processes configure vector control and seccomp"
)]

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;

use allocatbelt::{Allocatbelt, Availability, CpuFeatures, FeaturePolicy, KernelSet, Policy};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

const GET_CONTROL: libc::c_int = 70;
const SET_CONTROL: libc::c_int = 69;
const CURRENT_MASK: libc::c_int = 3;
const OFF: libc::c_ulong = 1;
const ON: libc::c_ulong = 2;
const CHILD: &str = "ALLOCATBELT_VECTOR_CONTROL_CHILD";
const TEST: &str = "vector_permissions_are_thread_local_and_fail_closed";

fn with(policy: FeaturePolicy) -> Policy {
  let mut result = Policy::DEFAULT;
  result.experimental_isa = policy;
  result
}

fn get_control() -> io::Result<libc::c_int> {
  // SAFETY: GET_CONTROL reads the calling thread's state and takes no pointer.
  let value = unsafe {
    libc::prctl(
      GET_CONTROL,
      0 as libc::c_ulong,
      0 as libc::c_ulong,
      0 as libc::c_ulong,
      0 as libc::c_ulong,
    )
  };
  if value < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(value)
  }
}

fn set_control(value: libc::c_ulong) -> io::Result<()> {
  // SAFETY: SET_CONTROL changes only this test thread's vector policy;
  // value is a control word, and the remaining arguments contain no pointer.
  let result = unsafe {
    libc::prctl(
      SET_CONTROL,
      value,
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

/// Installs an allocation-free filter before exec, denying only GET_CONTROL.
fn refuse_query() -> io::Result<()> {
  fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
  }
  let filter = [
    insn(0x20, 0, 0, 0), // BPF_LD | BPF_W | BPF_ABS: syscall number
    insn(0x15, 0, 3, libc::SYS_prctl as u32),
    insn(0x20, 0, 0, 16), // seccomp_data.args[0], little-endian low word
    insn(0x15, 0, 1, GET_CONTROL as u32),
    insn(0x06, 0, 0, 0x0005_0000 | libc::EPERM as u32), // RET_ERRNO
    insn(0x06, 0, 0, 0x7fff_0000),                      // RET_ALLOW
  ];
  let prog = libc::sock_fprog {
    len: filter.len() as u16,
    filter: filter.as_ptr().cast_mut(),
  };
  // SAFETY: NO_NEW_PRIVS takes an integer flag and no pointer.
  let result = unsafe {
    libc::prctl(
      libc::PR_SET_NO_NEW_PRIVS,
      1 as libc::c_ulong,
      0 as libc::c_ulong,
      0 as libc::c_ulong,
      0 as libc::c_ulong,
    )
  };
  if result < 0 {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: prog and its filter are live, initialized and have the kernel's
  // layout; the kernel copies them synchronously. Every other syscall is allowed.
  let result = unsafe {
    libc::prctl(
      libc::PR_SET_SECCOMP,
      2 as libc::c_ulong,
      &raw const prog,
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

fn child(mode: &'static str) {
  let mut command = Command::new(std::env::current_exe().unwrap());
  command
    .args(["--exact", TEST, "--nocapture"])
    .env(CHILD, mode);
  // SAFETY: this pre-exec hook performs only allocation-free prctl syscalls,
  // with stack-local data; it does not access allocator, std or user locks.
  unsafe {
    command.pre_exec(move || match mode {
      "off" => set_control(OFF << 2), // OFF on next exec, current state unchanged
      "denied" => refuse_query(),
      _ => unreachable!(),
    });
  }
  assert!(
    command.status().unwrap().success(),
    "vector-control child failed: {mode}"
  );
}

fn unavailable_here() {
  GLOBAL.configure(with(FeaturePolicy::Prefer)).unwrap();
  assert_eq!(GLOBAL.kernel_set(), KernelSet::Baseline);
  assert!(matches!(
    GLOBAL.report().detected.experimental_isa,
    Availability::Unavailable { .. }
  ));
  let before = GLOBAL.policy();
  assert!(GLOBAL.configure(with(FeaturePolicy::Require)).is_err());
  assert_eq!(
    GLOBAL.policy(),
    before,
    "a rejected policy must change nothing"
  );
}

fn mixed_threads() {
  assert_eq!(get_control().unwrap() & CURRENT_MASK, OFF as libc::c_int);
  // Hardware V remains visible even when this thread cannot execute it.
  assert!(GLOBAL.cpu_features().contains(CpuFeatures::RVV));
  unavailable_here();
  let (commands, receive) = mpsc::channel::<FeaturePolicy>();
  let (done, completed) = mpsc::channel();
  std::thread::scope(|scope| {
    let enabled = scope.spawn(move || {
      set_control(ON).unwrap();
      assert_eq!(get_control().unwrap() & CURRENT_MASK, ON as libc::c_int);
      assert!(GLOBAL.cpu_features().contains(CpuFeatures::RVV));
      GLOBAL.configure(with(FeaturePolicy::Require)).unwrap();
      assert_eq!(GLOBAL.kernel_set(), KernelSet::Rvv);
      assert_eq!(
        GLOBAL.report().detected.experimental_isa,
        Availability::Available
      );
      done.send(()).unwrap();
      for policy in receive {
        assert_eq!(GLOBAL.policy().experimental_isa, policy);
        assert_eq!(
          GLOBAL.kernel_set(),
          match policy {
            FeaturePolicy::Disable => KernelSet::Baseline,
            FeaturePolicy::Prefer => KernelSet::Rvv,
            _ => panic!("unexpected test policy"),
          }
        );
        done.send(()).unwrap();
      }
    });
    completed.recv().unwrap();
    let before = GLOBAL.policy();
    assert_eq!(before.experimental_isa, FeaturePolicy::Require);
    assert!(GLOBAL.configure(with(FeaturePolicy::Require)).is_err());
    assert_eq!(GLOBAL.policy(), before);
    assert_eq!(GLOBAL.kernel_set(), KernelSet::Baseline);
    assert!(matches!(
      GLOBAL.report().detected.experimental_isa,
      Availability::Unavailable { .. }
    ));
    for policy in [FeaturePolicy::Disable, FeaturePolicy::Prefer] {
      GLOBAL.configure(with(policy)).unwrap();
      commands.send(policy).unwrap();
      completed.recv().unwrap();
      assert_eq!(GLOBAL.kernel_set(), KernelSet::Baseline);
    }
    drop(commands);
    enabled.join().unwrap();
  });
  assert_eq!(get_control().unwrap() & CURRENT_MASK, OFF as libc::c_int);
  GLOBAL.configure(Policy::DEFAULT).unwrap();
}

#[test]
fn vector_permissions_are_thread_local_and_fail_closed() {
  match std::env::var(CHILD).ok().as_deref() {
    Some("denied") => {
      assert_eq!(get_control().unwrap_err().raw_os_error(), Some(libc::EPERM));
      unavailable_here();
      eprintln!("riscv vector control: refused query selects baseline");
    }
    Some("off") => {
      mixed_threads();
      eprintln!("riscv vector control: OFF and ON threads select independently");
    }
    None => {
      if !GLOBAL.cpu_features().contains(CpuFeatures::RVV) || get_control().is_err() {
        assert!(
          std::env::var_os("ALLOCATBELT_REQUIRE_VECTOR_CONTROL").is_none(),
          "this check requires hardware V and a working vector-control interface"
        );
        unavailable_here();
        eprintln!("riscv vector control: mixed-thread check unavailable on this host");
        return;
      }
      child("denied");
      child("off");
    }
    Some(_) => panic!("unknown vector-control child mode"),
  }
}
