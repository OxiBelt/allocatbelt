//! Checks typed runtime startup failure and caller-owned resource cleanup.
//!
//! Run under an externally verified `io_uring_setup` -> `EPERM` policy as a
//! non-root process with no capabilities, no-new-privileges and seccomp enabled.
//! An unrestricted invocation is expected to fail this acceptance check.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::CompiledCapabilities;
use allocatbelt::runtime::managed::{OperationRequest, ResourceLimits, ResourceScope};
use allocatbelt::runtime::uring::{UringConfig, UringRuntime, UringStartErrorKind};

const _: () = assert!(CompiledCapabilities::CURRENT.runtime_io_uring);

fn field<'a>(status: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
  status
    .lines()
    .find_map(|line| line.strip_prefix(key))
    .map(str::trim)
    .ok_or_else(|| format!("missing process status field {key}").into())
}

fn thread_ids() -> Result<Vec<u32>, Box<dyn Error>> {
  let mut ids = Vec::new();
  for entry in fs::read_dir("/proc/self/task")? {
    let name = entry?
      .file_name()
      .into_string()
      .map_err(|_| "non-UTF-8 task identity")?;
    ids.push(name.parse()?);
  }
  ids.sort_unstable();
  Ok(ids)
}

fn main() -> Result<(), Box<dyn Error>> {
  let status = fs::read_to_string("/proc/self/status")?;
  assert_eq!(field(&status, "NoNewPrivs:")?, "1");
  assert_eq!(field(&status, "Seccomp:")?, "2");
  for key in ["Uid:", "Gid:"] {
    let ids = field(&status, key)?
      .split_whitespace()
      .map(str::parse::<u32>)
      .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(ids.len(), 4);
    assert!(ids[0] != 0 && ids.iter().all(|&id| id == ids[0]));
  }
  for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
    assert_eq!(u64::from_str_radix(field(&status, key)?, 16)?, 0);
  }

  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 4096,
    disk_concurrent_ops: 1,
    network_concurrent_ops: 0,
  });
  let empty = scope.snapshot();
  let buffer = scope.try_alloc_zeroed(64)?;
  let permit = scope.try_acquire(OperationRequest {
    disk: 1,
    network: 0,
  })?;
  let held = scope.snapshot();
  assert!(held.managed_memory >= 64);
  assert_eq!((held.disk_ops, held.network_ops), (1, 0));
  let before_threads = thread_ids()?;
  assert_eq!(before_threads.len(), 1);

  let failure = match UringRuntime::start(UringConfig { max_operations: 1 }, scope.clone()) {
    Err(error) => error,
    Ok(mut runtime) => {
      runtime.shutdown()?;
      return Err("io_uring setup succeeded in the denied acceptance lane".into());
    }
  };
  match &failure.kind {
    UringStartErrorKind::Ring { phase, error } => {
      assert_eq!(*phase, "setup");
      assert_eq!(error.raw_os_error(), Some(libc::EPERM));
      assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    other => return Err(format!("unexpected startup failure: {other:?}").into()),
  }
  assert_eq!(scope.snapshot(), held);
  assert!(buffer.iter().all(|&byte| byte == 0));
  drop(permit);
  drop(buffer);
  assert_eq!(scope.snapshot(), empty);
  let recovered_buffer = scope.try_alloc_zeroed(4096)?;
  let recovered_permit = scope.try_acquire(OperationRequest {
    disk: 1,
    network: 0,
  })?;
  assert_eq!(recovered_buffer.len(), 4096);
  assert_eq!(scope.snapshot().disk_ops, 1);
  drop(recovered_permit);
  drop(recovered_buffer);
  assert_eq!(scope.snapshot(), empty);

  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    let observed_threads = thread_ids()?;
    assert!(
      Instant::now() < deadline,
      "thread cleanup check exceeded its deadline"
    );
    if observed_threads == before_threads {
      break;
    }
    thread::sleep(Duration::from_millis(10));
  }
  let final_threads = thread_ids()?;
  assert!(
    Instant::now() < deadline,
    "thread cleanup confirmation exceeded its deadline"
  );
  assert_eq!(final_threads, before_threads);
  println!(
    "URING_DENIED_START_PASS\tsetup\t{}\tresources_unchanged\trefunds_zero\tthreads_closed",
    libc::EPERM
  );
  Ok(())
}
