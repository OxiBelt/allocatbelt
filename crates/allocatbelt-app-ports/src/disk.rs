//! Deterministic positional disk I/O through the owned filesystem runtime.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use allocatbelt::runtime::Job;
use allocatbelt::runtime::asynchronous::{AsyncJoinError, OwnedTaskScope};
use allocatbelt::runtime::fs::{FileIoOutcome, FsHandle, FsSubmissionError, OwnedFile};
use allocatbelt::runtime::managed::{ManagedBuf, ResourceScope, ResourceSnapshot};

use crate::memory::{checksum, pattern_byte};
use crate::{PortResult, join_message, message};

/// Maximum payload length for the functional example.
pub const MAX_DISK_BYTES: usize = 1 << 20;
/// Maximum sparse offset for the functional example.
pub const MAX_DISK_OFFSET: u64 = 1 << 20;
const MAX_TEMP_DIR_TRIES: usize = 32;

/// Owned inputs returned unchanged if opening a prepared file is rejected
/// before a blocking job is admitted.
pub type PreparedOpenInput = (PathBuf, OpenOptions);
/// Owned inputs returned unchanged if a positional write is rejected before
/// a blocking job is admitted.
pub type PositionalWriteInput = (OwnedFile, ManagedBuf, u64);

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

/// Bounded positional file transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskConfig {
  /// Payload length in bytes.
  pub bytes: usize,
  /// Explicit write/read offset.
  pub offset: u64,
  /// Deterministic payload seed.
  pub seed: u64,
}

impl Default for DiskConfig {
  fn default() -> Self {
    Self {
      // Exceeds two current 64 KiB filesystem chunks so the example exercises
      // repeated bounded positional operations.
      bytes: 3 * 64 * 1024 + 17,
      offset: 4096,
      seed: 0xa409_3822_299f_31d0,
    }
  }
}

/// Result of the write, sync, explicit-offset readback and cleanup sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskReport {
  /// The positional offset used for both write and read.
  pub offset: u64,
  /// Bytes written and read back.
  pub bytes: usize,
  /// Payload checksum verified after readback.
  pub checksum: u64,
  /// Resource charges at transaction completion.
  pub resources_after_cleanup: ResourceSnapshot,
  /// Whether the unique temporary directory was explicitly removed.
  pub temp_directory_removed: bool,
}

/// Deterministic file byte shared with the memory and HTTP adapters.
#[must_use]
pub fn payload_byte(seed: u64, index: usize) -> u8 {
  pattern_byte(seed ^ 0x082e_fa98_ec4e_6c89, index)
}

/// A directory created by this process and safe to remove as one owned tree.
/// The directory and `create_new` file are created synchronously before any
/// cancellable work. Later pool opens never create a path, so cleanup may
/// remove the tree even if an admitted open job is still queued.
struct TempDir {
  path: PathBuf,
  owned: bool,
}

impl TempDir {
  fn create() -> io::Result<Self> {
    Self::create_with(|| {
      let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
      std::env::temp_dir().join(format!("allocatbelt-app-port-{}-{id}", std::process::id()))
    })
  }

  fn create_with(mut candidate: impl FnMut() -> PathBuf) -> io::Result<Self> {
    for _ in 0..MAX_TEMP_DIR_TRIES {
      let path = candidate();
      match create_private_dir(&path) {
        Ok(()) => return Ok(Self { path, owned: true }),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
      }
    }
    Err(io::Error::new(
      io::ErrorKind::AlreadyExists,
      "could not reserve a unique application-port temp directory",
    ))
  }

  fn file_path(&self) -> PathBuf {
    self.path.join("payload.bin")
  }

  fn create_file(&self) -> io::Result<PathBuf> {
    let path = self.file_path();
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    drop(options.open(&path)?);
    Ok(path)
  }

  fn cleanup(&mut self) -> io::Result<()> {
    if self.owned {
      fs::remove_dir_all(&self.path)?;
      self.owned = false;
    }
    Ok(())
  }
}

fn create_private_dir(path: &std::path::Path) -> io::Result<()> {
  let mut builder = fs::DirBuilder::new();
  #[cfg(unix)]
  builder.mode(0o700);
  builder.create(path)
}

fn existing_file_options() -> OpenOptions {
  let mut options = OpenOptions::new();
  options.read(true).write(true);
  options
}

/// Submits an open for a caller-prepared path without losing retry inputs.
///
/// A returned error is a pre-admission rejection; callers can inspect its
/// kind and recover the exact path/options with
/// [`FsSubmissionError::into_input`].
/// Once this returns a job, dropping the job detaches the open and its owned
/// inputs remain with the blocking worker until completion or queue cancel.
pub fn submit_prepared_open(
  fs_handle: &FsHandle,
  path: PathBuf,
  options: OpenOptions,
) -> Result<Job<io::Result<OwnedFile>>, FsSubmissionError<PreparedOpenInput>> {
  fs_handle.open(path, options)
}

/// Submits a positional write with an explicit recoverable pre-admission
/// boundary. A rejection returns the original file, managed buffer and offset;
/// an admitted operation's partial count or I/O error is instead returned in
/// [`FileIoOutcome`] and must not be replayed automatically.
pub fn submit_positional_write(
  fs_handle: &FsHandle,
  file: OwnedFile,
  buffer: ManagedBuf,
  offset: u64,
) -> Result<Job<FileIoOutcome>, FsSubmissionError<PositionalWriteInput>> {
  fs_handle.write_at(file, buffer, offset)
}

async fn open_prepared_file(fs_handle: &FsHandle, path: PathBuf) -> PortResult<OwnedFile> {
  submit_prepared_open(fs_handle, path, existing_file_options())?
    .await
    .map_err(join_message)?
    .map_err(Into::into)
}

impl Drop for TempDir {
  fn drop(&mut self) {
    if self.owned {
      let _ = fs::remove_dir_all(&self.path);
    }
  }
}

async fn transaction(
  fs_handle: &FsHandle,
  resources: &ResourceScope,
  config: DiskConfig,
) -> PortResult<DiskReport> {
  if config.bytes == 0
    || config.bytes > MAX_DISK_BYTES
    || config.offset > MAX_DISK_OFFSET
    || config.offset.checked_add(config.bytes as u64).is_none()
  {
    return Err(message("disk config exceeds its functional bounds").into());
  }

  let mut temp = TempDir::create()?;
  // Establish the unique file before yielding to cancellable asynchronous
  // work. The pool open below cannot create a file after `temp` is dropped.
  let path = temp.create_file()?;
  let file = open_prepared_file(fs_handle, path).await?;

  let mut payload = resources.try_alloc_zeroed(config.bytes)?;
  let Some(bytes) = payload.get_mut() else {
    return Err(message("new disk payload buffer is shared").into());
  };
  for (index, byte) in bytes.iter_mut().enumerate() {
    *byte = payload_byte(config.seed, index);
  }
  let expected_checksum = checksum(payload.as_slice());

  let FileIoOutcome {
    file,
    buffer: payload,
    bytes: written,
    error,
  } = submit_positional_write(fs_handle, file, payload, config.offset)?
    .await
    .map_err(join_message)?;
  if written != config.bytes {
    return Err(message(format!("short positional write: {written} bytes")).into());
  }
  if let Some(error) = error {
    return Err(error.into());
  }
  drop(payload);

  let (file, flush_result) = fs_handle
    .flush(file)
    .map_err(|error| message(format!("filesystem flush rejected: {:?}", error.kind)))?
    .await
    .map_err(join_message)?;
  flush_result?;

  let (file, sync_result) = fs_handle
    .sync_all(file)
    .map_err(|error| message(format!("filesystem sync rejected: {:?}", error.kind)))?
    .await
    .map_err(join_message)?;
  sync_result?;

  let readback = resources.try_alloc_zeroed(config.bytes)?;
  let FileIoOutcome {
    file,
    buffer: readback,
    bytes: read,
    error,
  } = fs_handle
    .read_at(file, readback, config.offset)
    .map_err(|error| message(format!("filesystem read rejected: {:?}", error.kind)))?
    .await
    .map_err(join_message)?;
  if read != config.bytes {
    return Err(message(format!("short positional read: {read} bytes")).into());
  }
  if let Some(error) = error {
    return Err(error.into());
  }
  let actual_checksum = checksum(readback.as_slice());
  if actual_checksum != expected_checksum {
    return Err(message("disk readback checksum mismatch").into());
  }
  drop(readback);
  drop(file);

  let resources_after_cleanup = resources.snapshot();
  if resources_after_cleanup.managed_memory != 0
    || resources_after_cleanup.disk_ops != 0
    || resources_after_cleanup.network_ops != 0
  {
    return Err(message("disk transaction retained a managed resource charge").into());
  }
  temp.cleanup()?;
  Ok(DiskReport {
    offset: config.offset,
    bytes: config.bytes,
    checksum: actual_checksum,
    resources_after_cleanup,
    temp_directory_removed: !temp.path.exists(),
  })
}

/// Runs the owned filesystem transaction in a bounded async task scope.
pub async fn run(
  scope: &OwnedTaskScope,
  fs_handle: FsHandle,
  resources: ResourceScope,
  config: DiskConfig,
) -> PortResult<DiskReport> {
  let job = scope
    .spawn(async move { transaction(&fs_handle, &resources, config).await })
    .map_err(|error| join_message(error.kind))?;
  job
    .await
    .map_err(|error: AsyncJoinError| join_message(error))?
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::sync::mpsc;
  use std::task::{Context, Poll, Waker};
  use std::time::Duration;

  use allocatbelt::runtime::fs::FsHandle;
  use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
  use allocatbelt::runtime::{Config, Resources, Runtime, ShutdownMode};

  use super::{MAX_TEMP_DIR_TRIES, TempDir, open_prepared_file, payload_byte};

  static TEST_ID: AtomicU64 = AtomicU64::new(1);

  #[test]
  fn payload_kernel_is_repeatable() {
    let first: Vec<u8> = (0..128).map(|index| payload_byte(12, index)).collect();
    assert_eq!(
      first,
      (0..128)
        .map(|index| payload_byte(12, index))
        .collect::<Vec<_>>()
    );
    assert_ne!(
      first,
      (0..128)
        .map(|index| payload_byte(13, index))
        .collect::<Vec<_>>()
    );
  }

  #[test]
  fn collision_retries_without_removing_or_overwriting_existing_directory() {
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
      "allocatbelt-app-port-test-{}-{id}",
      std::process::id()
    ));
    let existing = root.join("existing");
    let created = root.join("created");
    fs::create_dir_all(&existing).unwrap();
    fs::write(existing.join("sentinel"), b"untouched").unwrap();
    let mut candidates = [existing.clone(), created.clone()].into_iter();
    let mut temp = TempDir::create_with(|| candidates.next().unwrap()).unwrap();
    assert_eq!(temp.path, created);
    assert_eq!(fs::read(existing.join("sentinel")).unwrap(), b"untouched");
    temp.cleanup().unwrap();
    assert!(existing.join("sentinel").exists());
    assert!(!created.exists());
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn dropping_the_owned_temp_directory_removes_its_contents() {
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-app-port-drop-{}-{id}",
      std::process::id()
    ));
    let temp = TempDir::create_with(|| path.clone()).unwrap();
    fs::write(temp.file_path(), b"owned payload").unwrap();
    drop(temp);
    assert!(!path.exists());
  }

  #[cfg(unix)]
  #[test]
  fn owned_temp_directory_is_created_with_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-app-port-mode-{}-{id}",
      std::process::id()
    ));
    let temp = TempDir::create_with(|| path.clone()).unwrap();
    let permissions = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(permissions, 0o700);
    drop(temp);
  }

  #[test]
  fn dropping_queued_async_open_cannot_recreate_a_cleaned_temp_path() {
    let mut runtime = Runtime::new(Config {
      workers: 1,
      max_outstanding: 3,
      capacity: Resources::ZERO,
    })
    .expect("blocking runtime should start");
    let handle = runtime.handle();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker = handle
      .try_spawn(Resources::ZERO, move |_| {
        started_tx.send(()).expect("test receiver remains alive");
        release_rx
          .recv_timeout(Duration::from_secs(5))
          .expect("test should release blocked filesystem worker");
      })
      .expect("blocking worker should accept its gate job");
    started_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("gate job should occupy filesystem worker");

    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-app-port-cancel-open-{}-{id}",
      std::process::id()
    ));
    let temp = TempDir::create_with(|| path.clone()).unwrap();
    let file_path = temp.create_file().unwrap();
    let absent_dir_path = path.with_extension("absent");
    let absent_temp = TempDir::create_with(|| absent_dir_path.clone()).unwrap();
    let absent_file_path = absent_temp.file_path();
    let ledger = ResourceScope::new(ResourceLimits {
      managed_memory: 0,
      disk_concurrent_ops: 2,
      network_concurrent_ops: 0,
    });
    let fs_handle = FsHandle::new(handle, ledger);
    let mut opening = Box::pin(open_prepared_file(&fs_handle, file_path.clone()));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
      Pin::as_mut(&mut opening).poll(&mut context),
      Poll::Pending
    ));
    let mut opening_absent = Box::pin(open_prepared_file(&fs_handle, absent_file_path.clone()));
    assert!(matches!(
      Pin::as_mut(&mut opening_absent).poll(&mut context),
      Poll::Pending
    ));

    // Dropping this future detaches the queued Fs job. Cleanup can proceed
    // because the queued open has no create flag and does not own the path.
    drop(opening);
    drop(opening_absent);
    drop(temp);
    assert!(!path.exists());
    release_tx.send(()).expect("gate job is still waiting");
    runtime
      .shutdown(ShutdownMode::Drain)
      .expect("queued non-creating open should finish after cleanup");
    assert!(!path.exists());
    assert!(absent_dir_path.is_dir());
    assert!(!absent_file_path.exists());
    drop(absent_temp);
    assert!(!absent_dir_path.exists());
    blocker.join().expect("gate job should complete normally");
  }

  #[test]
  fn exhausted_collision_search_does_not_claim_any_existing_path() {
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-app-port-collision-{}-{id}",
      std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    let result = TempDir::create_with(|| path.clone());
    assert!(result.is_err());
    assert!(path.is_dir());
    fs::remove_dir(path).unwrap();
    assert_eq!(MAX_TEMP_DIR_TRIES, 32);
  }
}
