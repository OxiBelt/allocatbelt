//! Experimental `mm_cid` shard selection (feature `experimental-rseq`)
//! across process boundaries (directive §9.2, Phase H): `fork` while
//! threads pick shards by `mm_cid`, a cpuset of one CPU, and a C library
//! that registered no rseq area because rseq was turned off
//! (`GLIBC_TUNABLES=glibc.pthread.rseq=0`) or a seccomp filter refused it.
//! Each case runs in a child process; the TLS per-thread shards must carry
//! the allocator wherever `mm_cid` cannot be read. Also the policy switched
//! back and forth while threads allocate.

#![cfg(feature = "experimental-rseq")]
#![allow(
  unsafe_code,
  reason = "the tests call fork, sched_setaffinity, alarm, _exit, waitpid and prctl"
)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use allocatbelt::{Allocatbelt, RseqPolicy, RseqUnavailable};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// The policy is process-wide: one test at a time sets it.
static POLICY: Mutex<()> = Mutex::new(());

/// Allocates and checks small blocks (cache refills pick the shard) and
/// page runs on `threads` threads at once; returns the largest `mm_cid`
/// any of them read, or `None` if none could be read.
fn allocate_on_threads(threads: usize, rounds: usize) -> (bool, Option<u32>) {
  let ok = AtomicBool::new(true);
  let max_cid = AtomicU32::new(0);
  let seen = AtomicBool::new(false);
  std::thread::scope(|s| {
    for t in 0..threads {
      let (ok, max_cid, seen) = (&ok, &max_cid, &seen);
      s.spawn(move || {
        let tag = t as u64;
        for i in 0..rounds {
          let blocks: Vec<Vec<u64>> = (0..16)
            .map(|j| {
              let len = if j == 0 { 20_000 } else { 1 + (i + j) % 60 };
              vec![tag << 32 | (i * 16 + j) as u64; len]
            })
            .collect();
          if !blocks.iter().all(|v| v.iter().all(|&x| x == v[0])) {
            ok.store(false, Ordering::Relaxed);
          }
          if let Some(cid) = GLOBAL.mm_cid() {
            seen.store(true, Ordering::Relaxed);
            max_cid.fetch_max(cid, Ordering::Relaxed);
          }
          if i % 16 == 0 {
            std::thread::yield_now();
          }
        }
      });
    }
  });
  let cid = seen
    .load(Ordering::Relaxed)
    .then(|| max_cid.load(Ordering::Relaxed));
  (ok.load(Ordering::Relaxed), cid)
}

/// Forks, runs `child` in the child with a watchdog, and returns its exit
/// status (0 when `child` returned true).
fn in_child(child: impl FnOnce() -> bool) -> i32 {
  // SAFETY: the child runs the allocator (the point of these tests) and
  // spawns threads, which glibc and musl support after `fork`, then
  // leaves with `_exit`.
  let pid = unsafe { libc::fork() };
  assert!(pid >= 0, "fork failed");
  if pid == 0 {
    // SAFETY: `alarm` only arms a timer, whose default action kills the
    // child if the allocator deadlocks.
    unsafe { libc::alarm(20) };
    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(child)).unwrap_or(false);
    // SAFETY: `_exit` ends the child without running the parent's atexit
    // handlers or the test harness again.
    unsafe { libc::_exit(if ok { 0 } else { 1 }) }
  }
  let mut status = 0;
  // SAFETY: waits for the child just created; `status` is a valid out
  // pointer.
  let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
  assert_eq!(r, pid);
  assert!(
    libc::WIFEXITED(status),
    "child killed (status {status:#x}; SIGALRM means it deadlocked)"
  );
  libc::WEXITSTATUS(status)
}

/// Sets the flag when dropped, so the busy threads stop even when an
/// assertion fails.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
  fn drop(&mut self) {
    self.0.store(true, Ordering::Relaxed);
  }
}

#[test]
fn children_forked_while_threads_pick_shards_by_mm_cid() {
  let _policy = POLICY
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner);
  let parent = GLOBAL.set_rseq_policy(RseqPolicy::Prefer).unwrap();
  eprintln!("rseq: {parent:?}");
  let stop = AtomicBool::new(false);
  std::thread::scope(|s| {
    let _stop = SetOnDrop(&stop);
    for t in 0..4u8 {
      let stop = &stop;
      s.spawn(move || {
        while !stop.load(Ordering::Relaxed) {
          let v: Vec<Vec<u8>> = (0..32).map(|i| vec![t; 1 + i * 37]).collect();
          drop(v);
          drop(vec![t; 300_000]);
        }
      });
    }
    for round in 0..50 {
      let status = in_child(|| {
        // The child inherits the policy and the forking thread's rseq
        // registration; its `mm_cid`s are those of its own address space.
        let s = GLOBAL.rseq_status();
        let (ok, cid) = allocate_on_threads(4, 200);
        s == parent
          && ok
          && GLOBAL.mm_cid().is_some() == parent.available.is_ok()
          && cid.is_some() == parent.available.is_ok()
          && cid.is_none_or(|c| c < 64)
      });
      assert_eq!(status, 0, "child {round} failed");
    }
  });
  GLOBAL.set_rseq_policy(RseqPolicy::Auto).unwrap();
}

#[test]
fn switching_the_policy_while_threads_allocate() {
  let _policy = POLICY
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner);
  let stop = AtomicBool::new(false);
  std::thread::scope(|s| {
    let _stop = SetOnDrop(&stop);
    let workers: Vec<_> = (0..8)
      .map(|_| s.spawn(|| allocate_on_threads(2, 400).0))
      .collect();
    let switcher = s.spawn(|| {
      let order = [RseqPolicy::Prefer, RseqPolicy::Disable, RseqPolicy::Auto];
      let mut i = 0;
      while !stop.load(Ordering::Relaxed) {
        let p = order[i % order.len()];
        let status = GLOBAL.set_rseq_policy(p).unwrap();
        // Another thread's refill may see the old or the new policy; this
        // one reads its own write.
        assert_eq!(status.policy, p);
        assert_eq!(
          status.active,
          p == RseqPolicy::Prefer && status.available.is_ok()
        );
        i += 1;
      }
      i
    });
    for w in workers {
      assert!(w.join().unwrap(), "a block was overwritten");
    }
    stop.store(true, Ordering::Relaxed);
    eprintln!("policy switched {} times", switcher.join().unwrap());
  });
  GLOBAL.set_rseq_policy(RseqPolicy::Auto).unwrap();
}

/// The CPUs the calling thread may run on.
fn allowed_cpus() -> libc::cpu_set_t {
  // SAFETY: `cpu_set_t` is plain data; zero is the empty set.
  let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
  // SAFETY: `set` is a valid out pointer of the size passed.
  let r = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut set) };
  assert_eq!(r, 0, "sched_getaffinity failed");
  set
}

fn set_allowed_cpus(set: &libc::cpu_set_t) {
  // SAFETY: `set` is a valid CPU set of the size passed.
  let r = unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), set) };
  assert_eq!(r, 0, "sched_setaffinity failed");
}

#[test]
fn a_cpuset_of_one_cpu_bounds_mm_cid() {
  let _policy = POLICY
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner);
  let status = GLOBAL.set_rseq_policy(RseqPolicy::Prefer).unwrap();
  let all = allowed_cpus();
  let first = (0..libc::CPU_SETSIZE as usize)
    // SAFETY: `c` is below `CPU_SETSIZE`, so within the set.
    .find(|&c| unsafe { libc::CPU_ISSET(c, &all) })
    .unwrap();
  // SAFETY: as in `allowed_cpus`.
  let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
  // SAFETY: `first` is below `CPU_SETSIZE`.
  unsafe { libc::CPU_SET(first, &mut one) };
  // A container limited to one CPU, as a new process: the child's address
  // space starts with only that CPU allowed.
  set_allowed_cpus(&one);
  let child = in_child(|| {
    let (ok, cid) = allocate_on_threads(16, 300);
    eprintln!("16 threads on CPU {first}: largest mm_cid {cid:?}");
    ok && cid.is_some() == status.available.is_ok() && cid.is_none_or(|c| c == 0)
  });
  set_allowed_cpus(&all);
  GLOBAL.set_rseq_policy(RseqPolicy::Auto).unwrap();
  assert_eq!(child, 0, "the child failed");
}

/// Set in a re-executed test binary: why glibc registered no rseq area.
const REFUSED: &str = "ALLOCATBELT_RSEQ_REFUSED";

/// Runs [`registered_no_area`] in a new process of this test binary, which
/// `command` starts without a glibc rseq registration.
#[cfg(target_env = "gnu")]
fn run_refused(why: &str, mut command: std::process::Command) {
  if GLOBAL.rseq_status().available == Err(RseqUnavailable::NotRegistered) {
    // This process is that case already (qemu-user, which also cannot
    // re-execute a foreign binary without binfmt_misc); the other tests
    // cover it.
    return eprintln!("{why}: skipped, this process has no rseq area either");
  }
  let out = match command
    .args([
      "--exact",
      "registered_no_area",
      "--nocapture",
      "--test-threads=1",
    ])
    .env(REFUSED, why)
    .output()
  {
    Ok(out) => out,
    // Only `pre_exec` fails: the sandbox this runs in forbids new seccomp
    // filters (or an emulator does not implement them).
    Err(e) => return eprintln!("{why}: skipped, cannot install the filter: {e}"),
  };
  let stderr = String::from_utf8_lossy(&out.stderr);
  eprintln!(
    "{why}: {}",
    stderr
      .lines()
      .find(|l| l.starts_with("rseq:"))
      .unwrap_or("?")
  );
  assert!(
    out.status.success(),
    "{why}: {}\n{stderr}",
    String::from_utf8_lossy(&out.stdout)
  );
}

#[test]
#[cfg(target_env = "gnu")]
fn glibc_rseq_turned_off_falls_back() {
  let mut c = std::process::Command::new(std::env::current_exe().unwrap());
  c.env("GLIBC_TUNABLES", "glibc.pthread.rseq=0");
  run_refused("tunable", c);
}

/// `AUDIT_ARCH_*` of this target (`uapi/linux/audit.h`).
#[cfg(target_env = "gnu")]
const AUDIT_ARCH: u32 = if cfg!(target_arch = "x86_64") {
  0xc000_003e
} else if cfg!(target_arch = "aarch64") {
  0xc000_00b7
} else {
  0xc000_00f3 // riscv64
};

#[test]
#[cfg(target_env = "gnu")]
fn seccomp_refusing_rseq_falls_back() {
  use std::os::unix::process::CommandExt;

  // A seccomp filter that fails rseq with EPERM and allows everything
  // else, as a hardened container might.
  let op = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
    code: code as u16,
    jt,
    jf,
    k,
  };
  let filter = [
    op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 4, 0, 0), // arch
    op(
      libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
      AUDIT_ARCH,
      0,
      3,
    ),
    op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0), // nr
    op(
      libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
      libc::SYS_rseq as u32,
      0,
      1,
    ),
    op(
      libc::BPF_RET | libc::BPF_K,
      libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
      0,
      0,
    ),
    op(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
  ];
  let prog = libc::sock_fprog {
    len: filter.len() as u16,
    filter: filter.as_ptr().cast_mut(),
  };
  let prog = &raw const prog as usize;
  let mut c = std::process::Command::new(std::env::current_exe().unwrap());
  // SAFETY: the closure only calls `prctl`, which is async-signal-safe,
  // with `prog`, which outlives the child's `exec` (`output` waits).
  unsafe { c.pre_exec(move || install_filter(prog)) };
  run_refused("seccomp", c);
}

/// Installs the seccomp filter program at `prog` (a `sock_fprog`) for the
/// calling process.
#[cfg(target_env = "gnu")]
fn install_filter(prog: usize) -> std::io::Result<()> {
  // SAFETY: sets a process flag; no memory is passed.
  if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
    return Err(std::io::Error::last_os_error());
  }
  // SAFETY: `prog` points to a valid `sock_fprog` whose filter array is
  // alive; the kernel copies both.
  if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, prog) } != 0 {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

/// Runs only when re-executed by the tests above: glibc registered no rseq
/// area, so `mm_cid` cannot be read and the TLS shards carry everything.
#[test]
fn registered_no_area() {
  let Ok(why) = std::env::var(REFUSED) else {
    return;
  };
  let status = GLOBAL.rseq_status();
  eprintln!("rseq: {why}: {status:?}");
  assert_eq!(status.available, Err(RseqUnavailable::NotRegistered));
  assert_eq!(GLOBAL.mm_cid(), None);
  let report = GLOBAL.report().to_string();
  assert!(
    report.contains(
      "rseq: compiled=true policy=auto detected=unavailable (not registered) effective=false"
    ),
    "{report}"
  );
  // `Require` fails and changes nothing, through either API.
  assert_eq!(
    GLOBAL.set_rseq_policy(RseqPolicy::Require),
    Err(RseqUnavailable::NotRegistered)
  );
  let mut require = allocatbelt::Policy::DEFAULT;
  require.rseq = RseqPolicy::Require;
  assert!(matches!(
    GLOBAL.configure(require),
    Err(allocatbelt::PolicyError::Unavailable {
      step: "not registered",
      ..
    })
  ));
  assert_eq!(GLOBAL.rseq_status(), status);
  // `Prefer` falls back to the per-thread shards.
  let prefer = GLOBAL.set_rseq_policy(RseqPolicy::Prefer).unwrap();
  assert!(!prefer.active);
  let (ok, cid) = allocate_on_threads(8, 300);
  assert!(ok);
  assert_eq!(cid, None);
  assert_eq!(in_child(|| allocate_on_threads(4, 100) == (true, None)), 0);
}
