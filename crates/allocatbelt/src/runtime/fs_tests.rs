use super::{DirectoryEntryOutcome, FsHandle, FsSubmissionErrorKind, OwnedFile};
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::{Config, JoinError, Resources, Runtime, ShutdownMode, SubmitErrorKind};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(8);
static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

#[test]
fn supplied_file_survives_unlink_mutations_and_recovery_without_cursor_reset() {
  let scratch = Scratch::new();
  let path = scratch.child("owned");
  fs::write(&path, b"abcdefgh").unwrap();
  let mut standard = open_options(true, true, false).open(&path).unwrap();
  standard.seek(SeekFrom::Start(5)).unwrap();
  let descriptor = standard.as_raw_fd();
  let mut runtime = runtime(1, 2);
  let scope = scope(0, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let file = OwnedFile::from_std(standard);
  fs::remove_file(&path).unwrap();
  let (file, metadata) = handle.file_metadata(file).unwrap().join().unwrap();
  assert_eq!(metadata.unwrap().len(), 8);
  let (file, truncated) = handle.set_len(file, 3).unwrap().join().unwrap();
  truncated.unwrap();
  let (file, changed) = handle
    .file_set_permissions(file, fs::Permissions::from_mode(0o600))
    .unwrap()
    .join()
    .unwrap();
  changed.unwrap();
  let mut recovered = file.into_std();
  assert_eq!(recovered.as_raw_fd(), descriptor);
  assert_eq!(recovered.stream_position().unwrap(), 5);
  let metadata = recovered.metadata().unwrap();
  assert_eq!(metadata.len(), 3);
  assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
  assert_eq!(scope.snapshot().disk_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn rejected_and_queued_cancelled_file_mutations_have_no_side_effects() {
  let scratch = Scratch::new();
  let path = scratch.child("unchanged");
  fs::write(&path, b"unchanged").unwrap();
  let mut runtime = runtime(1, 1);
  let (blocker, started, release) = gated_job(&runtime);
  started.recv_timeout(WATCHDOG).unwrap();
  let scope = scope(0, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let supplied = open_options(true, true, false).open(&path).unwrap();
  let descriptor = supplied.as_raw_fd();
  let error = handle
    .set_len(OwnedFile::from_std(supplied), 0)
    .unwrap_err();
  assert_eq!(
    error.kind,
    FsSubmissionErrorKind::Runtime(SubmitErrorKind::Full)
  );
  let (returned, length) = error.into_input();
  assert_eq!(length, 0);
  assert_eq!(returned.into_std().as_raw_fd(), descriptor);
  assert_eq!(fs::read(&path).unwrap(), b"unchanged");
  assert_eq!(scope.snapshot().disk_ops, 0);
  release.send(()).unwrap();
  blocker.join().unwrap();
  runtime.shutdown(ShutdownMode::Drain).unwrap();

  let mut runtime = self::runtime(1, 2);
  let (blocker, started, release) = gated_job(&runtime);
  started.recv_timeout(WATCHDOG).unwrap();
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let file = OwnedFile::from_std(open_options(true, true, false).open(&path).unwrap());
  let job = handle.set_len(file, 0).unwrap();
  assert_eq!(scope.snapshot().disk_ops, 1);
  job.cancel();
  release.send(()).unwrap();
  assert!(matches!(job.join(), Err(JoinError::Cancelled)));
  assert_eq!(fs::read(&path).unwrap(), b"unchanged");
  assert_eq!(scope.snapshot().disk_ops, 0);
  blocker.join().unwrap();
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn failed_truncation_returns_the_original_read_only_descriptor() {
  let scratch = Scratch::new();
  let path = scratch.child("read-only-mutation");
  fs::write(&path, b"retain").unwrap();
  let standard = File::open(&path).unwrap();
  let descriptor = standard.as_raw_fd();
  let mut runtime = runtime(1, 2);
  let scope = scope(0, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let (file, error) = handle
    .set_len(OwnedFile::from_std(standard), 0)
    .unwrap()
    .join()
    .unwrap();
  assert!(error.is_err());
  let mut returned = file.into_std();
  assert_eq!(returned.as_raw_fd(), descriptor);
  let mut contents = String::new();
  returned.read_to_string(&mut contents).unwrap();
  assert_eq!(contents, "retain");
  assert_eq!(scope.snapshot().disk_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn path_ports_preserve_relative_links_dangling_links_and_nonempty_directories() {
  let scratch = Scratch::new();
  let directory = scratch.child("directory");
  fs::create_dir(&directory).unwrap();
  let original = directory.join("original");
  let hard = directory.join("hard");
  let symbolic = directory.join("symbolic");
  fs::write(&original, b"linked").unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(0, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  handle
    .hard_link(original.clone(), hard.clone())
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  handle
    .symlink(PathBuf::from("original"), symbolic.clone())
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(
    handle
      .canonicalize(symbolic.clone())
      .unwrap()
      .join()
      .unwrap()
      .unwrap(),
    fs::canonicalize(&original).unwrap()
  );
  handle
    .set_permissions(hard.clone(), fs::Permissions::from_mode(0o640))
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(
    fs::metadata(&original).unwrap().permissions().mode() & 0o777,
    0o640
  );
  assert!(
    handle
      .remove_dir(directory.clone())
      .unwrap()
      .join()
      .unwrap()
      .is_err()
  );
  fs::remove_file(&original).unwrap();
  assert!(
    !handle
      .try_exists(symbolic.clone())
      .unwrap()
      .join()
      .unwrap()
      .unwrap()
  );
  assert_eq!(fs::read(&hard).unwrap(), b"linked");
  fs::remove_file(hard).unwrap();
  fs::remove_file(symbolic).unwrap();
  handle
    .remove_dir(directory)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(scope.snapshot().disk_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

struct Scratch(PathBuf);

impl Scratch {
  fn new() -> Self {
    let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("allocatbelt-fs-{}-{id}", std::process::id()));
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

fn wait_until(mut ready: impl FnMut() -> bool) {
  let deadline = Instant::now() + WATCHDOG;
  while !ready() {
    assert!(
      Instant::now() < deadline,
      "timed out waiting for filesystem state"
    );
    thread::yield_now();
  }
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

fn open_file(path: PathBuf, options: OpenOptions) -> OwnedFile {
  options.open(path).map(|file| OwnedFile { file }).unwrap()
}

fn open_options(read: bool, write: bool, create: bool) -> OpenOptions {
  let mut options = OpenOptions::new();
  options.read(read).write(write).create(create);
  options
}

fn wait_for_directory_entry(
  fs_handle: &FsHandle,
  directory: super::Directory,
) -> DirectoryEntryOutcome {
  fs_handle.next_entry(directory).unwrap().join().unwrap()
}

#[test]
fn joined_result_keeps_managed_charge_until_its_buffer_is_dropped() {
  let scratch = Scratch::new();
  let path = scratch.child("data");
  fs::write(&path, b"resource-retention").unwrap();
  let mut runtime = runtime(1, 4);
  let scope = scope(1024, 1);
  let fs_handle = FsHandle::new(runtime.handle(), scope.clone());
  let file = fs_handle
    .open(path, open_options(true, false, false))
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let buffer = scope.try_alloc_zeroed(32).unwrap();
  let charge = buffer.charged_bytes();
  let outcome = fs_handle.read(file, buffer).unwrap().join().unwrap();
  assert!(outcome.error.is_none());
  assert_eq!(&outcome.buffer[..outcome.bytes], b"resource-retention");
  assert_eq!(scope.snapshot().managed_memory, charge);
  assert_eq!(scope.snapshot().disk_ops, 0);
  drop(outcome);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn full_scheduler_rejection_returns_exact_path_and_releases_disk_permit() {
  let scratch = Scratch::new();
  let path = scratch.child("will-not-open-yet");
  let mut runtime = runtime(1, 1);
  let (_blocker, started, release) = gated_job(&runtime);
  started.recv_timeout(WATCHDOG).unwrap();
  let scope = scope(0, 1);
  let fs_handle = FsHandle::new(runtime.handle(), scope.clone());
  let error = fs_handle.metadata(path.clone()).unwrap_err();
  assert_eq!(
    error.kind,
    FsSubmissionErrorKind::Runtime(SubmitErrorKind::Full)
  );
  assert_eq!(error.into_input(), path);
  assert_eq!(scope.snapshot().disk_ops, 0);
  release.send(()).unwrap();
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn running_detached_operation_keeps_its_permit_and_buffer_until_completion() {
  let mut runtime = runtime(1, 2);
  let scope = scope(64, 1);
  let fs_handle = FsHandle::new(runtime.handle(), scope.clone());
  let buffer = scope.try_alloc_zeroed(32).unwrap();
  let charged = buffer.charged_bytes();
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let job = fs_handle
    .submit((buffer,), move |(buffer,), _| {
      started_tx.send(()).unwrap();
      let _ = release_rx.recv_timeout(WATCHDOG);
      buffer
    })
    .unwrap();
  started_rx.recv_timeout(WATCHDOG).unwrap();
  drop(job);
  assert_eq!(scope.snapshot().disk_ops, 1);
  assert_eq!(scope.snapshot().managed_memory, charged);
  release_tx.send(()).unwrap();
  wait_until(|| scope.snapshot().disk_ops == 0 && scope.snapshot().managed_memory == 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

struct DropGate {
  began: Sender<()>,
  release: Receiver<()>,
}

impl Drop for DropGate {
  fn drop(&mut self) {
    let _ = self.began.send(());
    let _ = self.release.recv_timeout(WATCHDOG);
  }
}

struct CleanupInput {
  gate: DropGate,
  buffer: crate::runtime::managed::ManagedBuf,
}

#[test]
fn queued_cancel_holds_permit_until_capture_cleanup_finishes() {
  let mut runtime = runtime(1, 2);
  let (blocker, started, release_worker) = gated_job(&runtime);
  started.recv_timeout(WATCHDOG).unwrap();
  let scope = scope(64, 1);
  let fs_handle = FsHandle::new(runtime.handle(), scope.clone());
  let buffer = scope.try_alloc_zeroed(24).unwrap();
  let charged = buffer.charged_bytes();
  let (drop_started_tx, drop_started_rx) = mpsc::channel();
  let (release_drop_tx, release_drop_rx) = mpsc::channel();
  let did_run = Arc::new(AtomicBool::new(false));
  let operation_ran = Arc::clone(&did_run);
  let job = fs_handle
    .submit(
      CleanupInput {
        gate: DropGate {
          began: drop_started_tx,
          release: release_drop_rx,
        },
        buffer,
      },
      move |CleanupInput {
              gate: _gate,
              buffer: _buffer,
            },
            _| {
        operation_ran.store(true, Ordering::SeqCst);
      },
    )
    .unwrap();
  job.cancel();
  release_worker.send(()).unwrap();
  drop_started_rx.recv_timeout(WATCHDOG).unwrap();
  assert_eq!(scope.snapshot().disk_ops, 1);
  assert_eq!(scope.snapshot().managed_memory, charged);
  release_drop_tx.send(()).unwrap();
  assert!(matches!(job.join(), Err(JoinError::Cancelled)));
  assert!(!did_run.load(Ordering::SeqCst));
  assert_eq!(scope.snapshot().disk_ops, 0);
  assert_eq!(scope.snapshot().managed_memory, 0);
  blocker.join().unwrap();
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn file_cursor_moves_with_owned_file_and_positional_io_leaves_it_unchanged() {
  let scratch = Scratch::new();
  let path = scratch.child("cursor");
  fs::write(&path, b"abcdefgh").unwrap();
  let mut runtime = runtime(2, 8);
  let scope = scope(256, 2);
  let fs_handle = FsHandle::new(runtime.handle(), scope.clone());
  let file = fs_handle
    .open(path.clone(), open_options(true, true, false))
    .unwrap()
    .join()
    .unwrap()
    .unwrap();

  let first = fs_handle
    .read(file, scope.try_alloc_zeroed(3).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(&first.buffer[..first.bytes], b"abc");
  let first_file = first.file;
  drop(first.buffer);
  let mut write_buffer = scope.try_alloc_zeroed(3).unwrap();
  write_buffer.get_mut().unwrap().copy_from_slice(b"XYZ");
  let written = fs_handle
    .write(first_file, write_buffer)
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(written.bytes, 3);
  assert!(written.error.is_none());
  let written_file = written.file;
  drop(written.buffer);
  let seek = fs_handle
    .seek(written_file, SeekFrom::Start(0))
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(seek.position.unwrap(), 0);
  let sequential = fs_handle
    .read(seek.file, scope.try_alloc_zeroed(6).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(&sequential.buffer[..sequential.bytes], b"abcXYZ");

  let sequential_file = sequential.file;
  drop(sequential.buffer);
  let next = fs_handle
    .read(sequential_file, scope.try_alloc_zeroed(1).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(&next.buffer[..next.bytes], b"g");
  let next_file = next.file;
  drop(next.buffer);
  let positional = fs_handle
    .read_at(next_file, scope.try_alloc_zeroed(1).unwrap(), 1)
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(&positional.buffer[..positional.bytes], b"b");
  let positional_file = positional.file;
  drop(positional.buffer);
  let sequential = fs_handle
    .read(positional_file, scope.try_alloc_zeroed(1).unwrap())
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(&sequential.buffer[..sequential.bytes], b"h");

  let sequential_file = sequential.file;
  drop(sequential.buffer);
  let mut patch = scope.try_alloc_zeroed(1).unwrap();
  patch.get_mut().unwrap()[0] = b'A';
  let positioned = fs_handle
    .write_at(sequential_file, patch, 0)
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(positioned.bytes, 1);
  assert!(positioned.error.is_none());
  let mut verification = File::open(path).unwrap();
  let mut bytes = Vec::new();
  verification.read_to_end(&mut bytes).unwrap();
  assert_eq!(&bytes, b"AbcXYZgh");
  drop(positioned);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn directory_iteration_returns_one_entry_per_job() {
  let scratch = Scratch::new();
  for name in ["one", "two", "three"] {
    fs::write(scratch.child(name), b"").unwrap();
  }
  let mut runtime = runtime(1, 2);
  let fs_handle = FsHandle::new(runtime.handle(), scope(0, 1));
  let opened = fs_handle
    .read_dir(scratch.0.clone())
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut directory = opened;
  let mut count = 0;
  loop {
    let outcome = wait_for_directory_entry(&fs_handle, directory);
    directory = outcome.directory;
    match outcome.entry.unwrap() {
      Some(entry) => {
        let (entry, metadata) = fs_handle.entry_metadata(entry).unwrap().join().unwrap();
        assert!(metadata.unwrap().is_file());
        let (_entry, file_type) = fs_handle.entry_file_type(entry).unwrap().join().unwrap();
        assert!(file_type.unwrap().is_file());
        count += 1;
      }
      None => break,
    }
  }
  assert_eq!(count, 3);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn write_error_returns_file_and_charged_buffer_without_progress() {
  let scratch = Scratch::new();
  let path = scratch.child("read-only");
  fs::write(&path, b"unchanged").unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(64, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let file = handle
    .open(path.clone(), open_options(true, false, false))
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut buffer = scope.try_alloc_zeroed(3).unwrap();
  buffer.get_mut().unwrap().copy_from_slice(b"new");
  let outcome = handle.write(file, buffer).unwrap().join().unwrap();
  assert_eq!(outcome.bytes, 0);
  assert!(outcome.error.is_some());
  assert_eq!(&*outcome.buffer, b"new");
  assert_eq!(scope.snapshot().managed_memory, 3);
  assert_eq!(scope.snapshot().disk_ops, 0);
  assert_eq!(fs::read(path).unwrap(), b"unchanged");
  let positioned = handle
    .seek(outcome.file, SeekFrom::Start(0))
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(positioned.position.unwrap(), 0);
  drop(outcome.buffer);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn positioned_write_preserves_linux_append_behavior() {
  let scratch = Scratch::new();
  let path = scratch.child("append");
  fs::write(&path, b"old").unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(64, 1);
  let handle = FsHandle::new(runtime.handle(), scope.clone());
  let mut options = OpenOptions::new();
  options.read(true).append(true);
  let file = handle
    .open(path.clone(), options)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut buffer = scope.try_alloc_zeroed(3).unwrap();
  buffer.get_mut().unwrap().copy_from_slice(b"new");
  let outcome = handle.write_at(file, buffer, 0).unwrap().join().unwrap();
  assert!(outcome.error.is_none());
  assert_eq!(outcome.bytes, 3);
  assert_eq!(fs::read(path).unwrap(), b"oldnew");
  let positioned = handle
    .seek(outcome.file, SeekFrom::Current(0))
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(positioned.position.unwrap(), 0);
  drop(outcome.buffer);
  let (file, result) = handle.sync_data(positioned.file).unwrap().join().unwrap();
  result.unwrap();
  let (_file, result) = handle.sync_all(file).unwrap().join().unwrap();
  result.unwrap();
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn shared_read_buffer_is_rejected_unchanged_before_disk_admission() {
  let scratch = Scratch::new();
  let path = scratch.child("shared");
  fs::write(&path, b"data").unwrap();
  let mut runtime = runtime(1, 2);
  let scope = scope(32, 1);
  let fs_handle = FsHandle::new(runtime.handle(), scope.clone());
  let file = open_file(path, open_options(true, false, false));
  let mut buffer = scope.try_alloc_zeroed(4).unwrap();
  buffer.get_mut().unwrap().copy_from_slice(b"keep");
  let other = buffer.clone();
  let error = fs_handle.read(file, buffer).unwrap_err();
  assert_eq!(
    error.kind,
    FsSubmissionErrorKind::Resource(crate::runtime::managed::ResourceError::Shared)
  );
  let (file, returned) = error.into_input();
  assert_eq!(returned.as_slice(), b"keep");
  assert_eq!(file.file.metadata().unwrap().len(), 4);
  assert_eq!(scope.snapshot().disk_ops, 0);
  assert_eq!(scope.snapshot().managed_memory, returned.charged_bytes());
  drop(other);
  drop(returned);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}
