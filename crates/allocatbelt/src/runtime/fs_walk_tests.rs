use super::{WalkEntryKind, WalkLimits, WalkStep};
use crate::runtime::fs::{FsHandle, FsSubmissionErrorKind};
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::{Config, JoinError, Resources, Runtime, ShutdownMode};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(8);
static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
  fn new() -> Self {
    let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("allocatbelt-walk-{}-{id}", std::process::id()));
    fs::create_dir(&path).unwrap();
    Self(path)
  }

  fn child(&self, name: &str) -> PathBuf {
    self.0.join(name)
  }
}

impl Drop for Scratch {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.0);
  }
}

fn runtime(workers: usize, max_outstanding: usize) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding,
    capacity: Resources::ZERO,
  })
  .unwrap()
}

fn scope(memory: usize, disk: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: memory,
    disk_concurrent_ops: disk,
    network_concurrent_ops: 0,
  })
}

fn gated_job(runtime: &Runtime) -> (crate::runtime::Job<()>, Receiver<()>, Sender<()>) {
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let job = runtime
    .try_spawn(Resources::ZERO, move |_| {
      started_tx.send(()).unwrap();
      let _ = release_rx.recv_timeout(WATCHDOG);
    })
    .unwrap();
  (job, started_rx, release_tx)
}

#[cfg(unix)]
struct WalkDrain {
  entries: Vec<(Vec<u8>, usize, WalkEntryKind)>,
  depth_limited: bool,
  charged_bytes: usize,
}

#[cfg(unix)]
fn drain_walk(
  handle: &FsHandle,
  mut walk: super::TreeWalk,
  mut path: crate::runtime::managed::ManagedBuf,
) -> WalkDrain {
  let mut entries = Vec::new();
  loop {
    let outcome = handle.walk_next(walk, path).unwrap().join().unwrap();
    walk = outcome.walk;
    path = outcome.path;
    match outcome.step {
      WalkStep::Entry {
        path_bytes,
        depth,
        kind,
        ..
      } => entries.push((path.as_slice()[..path_bytes].to_vec(), depth, kind)),
      WalkStep::Complete { depth_limited } => {
        return WalkDrain {
          entries,
          depth_limited,
          charged_bytes: path.charged_bytes(),
        };
      }
      WalkStep::Yielded => {}
      other => panic!("unexpected walk result: {other:?}"),
    }
  }
}

#[cfg(unix)]
#[test]
fn recursive_walk_streams_one_charged_non_utf8_path_per_job() {
  use std::os::unix::ffi::{OsStrExt, OsStringExt};

  let scratch = Scratch::new();
  let nested = scratch.child("nested");
  fs::create_dir(&nested).unwrap();
  let non_utf8 = std::ffi::OsString::from_vec(vec![b'n', 0xff, b'm']);
  fs::write(nested.join(&non_utf8), b"x").unwrap();
  let symlink = scratch.child("link");
  std::os::unix::fs::symlink(&nested, &symlink).unwrap();
  let path_limit = [
    scratch.0.as_os_str().as_bytes().len(),
    nested.as_os_str().as_bytes().len(),
    nested.join(&non_utf8).as_os_str().as_bytes().len(),
    symlink.as_os_str().as_bytes().len(),
  ]
  .into_iter()
  .max()
  .unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(path_limit, 2);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let walk = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 16,
        max_depth: 8,
        max_path_bytes: path_limit,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let path = scope.try_alloc_zeroed(path_limit).unwrap();
  let entries = drain_walk(&handle, walk, path);
  assert!(!entries.depth_limited);
  assert_eq!(entries.charged_bytes, path_limit);
  assert_eq!(entries.entries.len(), 4); // root, nested directory, file, symlink
  assert!(entries.entries.iter().any(|(path, depth, kind)| {
    *depth == 2 && *kind == WalkEntryKind::File && path.ends_with(&[b'n', 0xff, b'm'])
  }));
  assert!(entries.entries.iter().any(|(path, depth, kind)| {
    *depth == 1 && *kind == WalkEntryKind::Symlink && path.ends_with(b"link")
  }));
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(scope.snapshot().disk_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn recursive_walk_depth_and_entry_limits_are_explicit_and_do_not_descend_late() {
  let scratch = Scratch::new();
  let child = scratch.child("child");
  fs::create_dir(&child).unwrap();
  fs::write(child.join("hidden"), b"").unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(2048, 2);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let depth_walk = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 16,
        max_depth: 0,
        max_path_bytes: 1024,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let depth = drain_walk(&handle, depth_walk, scope.try_alloc_zeroed(1024).unwrap());
  assert_eq!(depth.entries.len(), 1);
  assert_eq!(depth.entries[0].1, 0);
  assert!(depth.depth_limited);

  let limited = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 2,
        max_depth: 8,
        max_path_bytes: 1024,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let path = scope.try_alloc_zeroed(1024).unwrap();
  let first = handle.walk_next(limited, path).unwrap().join().unwrap();
  assert!(matches!(first.step, WalkStep::Entry { depth: 0, .. }));
  let second = handle
    .walk_next(first.walk, first.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(
    second.step,
    WalkStep::Entry {
      entry_limit_reached: true,
      ..
    }
  ));
  let third = handle
    .walk_next(second.walk, second.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(third.step, WalkStep::EntryLimitReached));
  drop(third.path);
  assert_eq!(scope.snapshot().disk_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn zero_entry_limit_skips_filesystem_and_terminal_path_errors_cannot_resume() {
  use std::os::unix::ffi::OsStrExt;

  let scratch = Scratch::new();
  let mut runtime = runtime(1, 2);
  let scope = scope(2048, 2);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let nonexistent = scratch.child("absent");
  let zero = handle
    .walk_dir(
      nonexistent,
      WalkLimits {
        max_entries: 0,
        max_depth: 1,
        max_path_bytes: 1024,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let zero = handle
    .walk_next(zero, scope.try_alloc_zeroed(1024).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(zero.step, WalkStep::EntryLimitReached));
  let repeated_limit = handle
    .walk_next(zero.walk, zero.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(repeated_limit.step, WalkStep::Terminated));
  drop(repeated_limit.path);

  let root = scratch.child("r");
  fs::create_dir(&root).unwrap();
  fs::write(root.join("name-too-long"), b"").unwrap();
  let root_len = root.as_os_str().as_bytes().len();
  let walk = handle
    .walk_dir(
      root,
      WalkLimits {
        max_entries: 8,
        max_depth: 4,
        max_path_bytes: root_len + 2,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let first = handle
    .walk_next(walk, scope.try_alloc_zeroed(root_len + 2).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(first.step, WalkStep::Entry { depth: 0, .. }));
  let error = handle
    .walk_next(first.walk, first.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(error.step, WalkStep::Error { .. }));
  let terminal = handle
    .walk_next(error.walk, error.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(terminal.step, WalkStep::Terminated));
  drop(terminal.path);
  assert_eq!(scope.snapshot().disk_ops, 0);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn recursive_walk_rejects_root_symlinks_and_short_or_shared_output_before_admission() {
  let scratch = Scratch::new();
  let directory = scratch.child("directory");
  fs::create_dir(&directory).unwrap();
  let link = scratch.child("root-link");
  std::os::unix::fs::symlink(&directory, &link).unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(512, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let result = handle
    .walk_dir(
      link.clone(),
      WalkLimits {
        max_entries: 4,
        max_depth: 2,
        max_path_bytes: 128,
      },
    )
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

  let link_with_separator = PathBuf::from(format!("{}/", link.display()));
  let result = handle
    .walk_dir(
      link_with_separator,
      WalkLimits {
        max_entries: 4,
        max_depth: 2,
        max_path_bytes: 128,
      },
    )
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

  let walk = handle
    .walk_dir(
      directory,
      WalkLimits {
        max_entries: 4,
        max_depth: 2,
        max_path_bytes: 128,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let small = scope.try_alloc_zeroed(127).unwrap();
  let error = handle.walk_next(walk, small).unwrap_err();
  assert_eq!(
    error.kind,
    FsSubmissionErrorKind::Resource(crate::runtime::managed::ResourceError::Invalid(
      crate::runtime::managed::ResourceKind::Memory
    ))
  );
  let (walk, small) = error.into_input();
  assert_eq!(small.len(), 127);
  assert_eq!(scope.snapshot().disk_ops, 0);
  drop((walk, small));

  let walk = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 4,
        max_depth: 2,
        max_path_bytes: 128,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let shared = scope.try_alloc_zeroed(128).unwrap();
  let clone = shared.clone();
  let error = handle.walk_next(walk, shared).unwrap_err();
  assert_eq!(
    error.kind,
    FsSubmissionErrorKind::Resource(crate::runtime::managed::ResourceError::Shared)
  );
  let (walk, shared) = error.into_input();
  assert_eq!(scope.snapshot().disk_ops, 0);
  drop((walk, shared, clone));
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn completed_walk_cursor_is_terminal_on_repoll() {
  let scratch = Scratch::new();
  let mut runtime = runtime(1, 2);
  let scope = scope(256, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let walk = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 4,
        max_depth: 0,
        max_path_bytes: 128,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let root = handle
    .walk_next(walk, scope.try_alloc_zeroed(128).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(root.step, WalkStep::Entry { depth: 0, .. }));
  let complete = handle
    .walk_next(root.walk, root.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(complete.step, WalkStep::Complete { .. }));
  let terminal = handle
    .walk_next(complete.walk, complete.path)
    .unwrap()
    .join()
    .unwrap();
  assert!(matches!(terminal.step, WalkStep::Terminated));
  drop(terminal.path);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn queued_walk_cancellation_retains_then_releases_cursor_buffer_and_disk_slot() {
  let scratch = Scratch::new();
  fs::write(scratch.child("item"), b"").unwrap();
  let mut runtime = runtime(1, 3);
  let scope = scope(256, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let walk = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 4,
        max_depth: 2,
        max_path_bytes: 128,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let (blocker, started, release) = gated_job(&runtime);
  started.recv_timeout(WATCHDOG).unwrap();
  let path = scope.try_alloc_zeroed(128).unwrap();
  let job = handle.walk_next(walk, path).unwrap();
  assert_eq!(scope.snapshot().disk_ops, 1);
  assert_eq!(scope.snapshot().managed_memory, 128);
  job.cancel();
  release.send(()).unwrap();
  blocker.join().unwrap();
  assert!(matches!(job.join(), Err(JoinError::Cancelled)));
  assert_eq!(scope.snapshot().disk_ops, 0);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn recursive_walk_yields_after_bounded_empty_frame_work() {
  let scratch = Scratch::new();
  let mut directory = scratch.0.clone();
  for index in 0..80 {
    directory.push(format!("d{index}"));
    fs::create_dir(&directory).unwrap();
  }
  let mut runtime = runtime(1, 2);
  let scope = scope(4096, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let walk = handle
    .walk_dir(
      scratch.0.clone(),
      WalkLimits {
        max_entries: 128,
        max_depth: 100,
        max_path_bytes: 4096,
      },
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut walk = walk;
  let mut path = scope.try_alloc_zeroed(4096).unwrap();
  let mut saw_yield = false;
  loop {
    let outcome = handle.walk_next(walk, path).unwrap().join().unwrap();
    walk = outcome.walk;
    path = outcome.path;
    match outcome.step {
      WalkStep::Entry { .. } => {}
      WalkStep::Yielded => saw_yield = true,
      WalkStep::Complete { .. } => break,
      other => panic!("unexpected walk result: {other:?}"),
    }
  }
  assert!(saw_yield);
  drop(path);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}
