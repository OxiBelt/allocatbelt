//! Bounded, owned filesystem operations for the blocking runtime.
//!
//! Every submitted operation first reserves one disk permit from its
//! [`ResourceScope`] and then one job slot from the explicitly supplied
//! blocking [`Handle`]. The permit stays with the queued request or running
//! closure until that request completes or is dropped during cancellation.
//! Rejected submissions return their input unchanged. Dropping a returned
//! [`Job`] detaches the operation; cancelling a queued job prevents the
//! operation from starting.
//!
//! Submitted filesystem operations use `std::fs` on the blocking pool. This
//! module does not start a runtime, restrict paths, or impose disk-space,
//! entry-count, or byte-rate limits. Directory iteration yields one entry per
//! submitted call, so it does not eagerly collect an unbounded listing.
//! Returned standard-library `DirEntry` values can perform further blocking
//! I/O when their methods are called directly; those calls bypass the pool
//! and its disk permits.
//!
//! [`OwnedFile`] is deliberately not `Clone`. Each file operation takes
//! ownership of it and returns it in the outcome. This prevents concurrent
//! operations through this API from racing on a shared file cursor. Calls on
//! one file happen in the order the caller transfers ownership to and submits
//! each next operation; callers must wait for an outcome before submitting the
//! next cursor-based operation. On Unix, positional operations use
//! `FileExt` and leave the sequential cursor unchanged.

use std::fs::{self, File, Metadata, OpenOptions, ReadDir};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

use crate::runtime::blocking::Handle;
use crate::runtime::error::SubmitErrorKind;
use crate::runtime::job::{CancellationToken, Job};
use crate::runtime::managed::{
  ManagedBuf, OperationPermit, OperationRequest, ResourceError, ResourceScope,
};
use crate::runtime::resources::Resources;

const IO_CHUNK: usize = 64 * 1024;

#[cfg(all(test, not(loom)))]
#[path = "fs_tests.rs"]
mod tests;

/// Why the filesystem operation was refused before admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsSubmissionErrorKind {
  /// The scope could not reserve one disk-operation slot.
  Resource(ResourceError),
  /// The blocking runtime rejected the job.
  Runtime(SubmitErrorKind),
}

impl std::fmt::Display for FsSubmissionErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Resource(error) => write!(f, "filesystem operation refused: {error}"),
      Self::Runtime(error) => write!(f, "filesystem operation refused: {error}"),
    }
  }
}

impl std::error::Error for FsSubmissionErrorKind {}

/// A refused filesystem submission, with its original owned input.
pub struct FsSubmissionError<I> {
  /// Why the operation was refused.
  pub kind: FsSubmissionErrorKind,
  /// The input, unchanged and available for another attempt.
  pub input: I,
}

impl<I> FsSubmissionError<I> {
  /// Returns the input that was not admitted.
  #[must_use]
  pub fn into_input(self) -> I {
    self.input
  }
}

impl<I> std::fmt::Debug for FsSubmissionError<I> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("FsSubmissionError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<I> std::fmt::Display for FsSubmissionError<I> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.kind)
  }
}

impl<I: 'static> std::error::Error for FsSubmissionError<I> {}

/// A file whose cursor is accessed through one owned operation at a time.
///
/// The wrapped file is not cloneable through this API. Move it into an
/// operation and use the file returned by that operation's outcome to submit
/// the next one.
pub struct OwnedFile {
  file: File,
}

impl std::fmt::Debug for OwnedFile {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("OwnedFile").finish_non_exhaustive()
  }
}

/// The returned file, managed buffer, progress count, and any I/O error.
///
/// Both inputs remain available after a partial read/write or an I/O error.
#[derive(Debug)]
pub struct FileIoOutcome {
  /// The file to use for the next operation.
  pub file: OwnedFile,
  /// The buffer supplied to the operation.
  pub buffer: ManagedBuf,
  /// Bytes read or written before completion or error.
  pub bytes: usize,
  /// The I/O error, if the call failed. A partial count is retained too.
  pub error: Option<io::Error>,
}

/// The file returned by a seek and its resulting cursor position.
#[derive(Debug)]
pub struct SeekOutcome {
  /// The file to use for the next operation.
  pub file: OwnedFile,
  /// The resulting offset, or the seek error.
  pub position: io::Result<u64>,
}

/// A streaming directory handle.
pub struct Directory {
  entries: ReadDir,
}

impl std::fmt::Debug for Directory {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Directory").finish_non_exhaustive()
  }
}

/// One directory iteration result and the handle needed to continue.
#[derive(Debug)]
pub struct DirectoryEntryOutcome {
  /// The directory handle to move into the next `next_entry` call.
  pub directory: Directory,
  /// The next entry, end of directory, or iteration error.
  pub entry: io::Result<Option<fs::DirEntry>>,
}

/// A filesystem front end using an existing blocking pool and resource scope.
#[derive(Clone)]
pub struct FsHandle {
  blocking: Handle,
  scope: ResourceScope,
}

impl FsHandle {
  /// Uses the explicitly supplied blocking pool and resource ledger.
  #[must_use]
  pub fn new(blocking: Handle, scope: ResourceScope) -> Self {
    Self { blocking, scope }
  }

  /// Opens `path` using the caller's standard-library policy.
  pub fn open(
    &self,
    path: PathBuf,
    options: OpenOptions,
  ) -> Result<Job<io::Result<OwnedFile>>, FsSubmissionError<(PathBuf, OpenOptions)>> {
    self.submit((path, options), |(path, options), _token| {
      options.open(path).map(|file| OwnedFile { file })
    })
  }

  /// Reads until the buffer is full, EOF is reached, an error occurs, or
  /// cancellation is observed between system calls.
  ///
  /// A shared buffer is rejected before admission because this API does not
  /// allocate a replacement or perform copy-on-write.
  pub fn read(
    &self,
    file: OwnedFile,
    mut buffer: ManagedBuf,
  ) -> Result<Job<FileIoOutcome>, FsSubmissionError<(OwnedFile, ManagedBuf)>> {
    if buffer.get_mut().is_none() {
      return Err(FsSubmissionError {
        kind: FsSubmissionErrorKind::Resource(ResourceError::Shared),
        input: (file, buffer),
      });
    }
    self.submit((file, buffer), |(mut file, mut buffer), token| {
      let mut bytes: usize = 0;
      let mut error = None;
      if let Some(storage) = buffer.get_mut() {
        while bytes < storage.len() {
          if token.is_cancelled() {
            error = Some(io::Error::new(
              io::ErrorKind::Interrupted,
              "filesystem operation cancelled",
            ));
            break;
          }
          let end = storage.len().min(bytes.saturating_add(IO_CHUNK));
          match file.file.read(&mut storage[bytes..end]) {
            Ok(0) => break,
            Ok(read) => bytes += read,
            Err(read_error) => {
              error = Some(read_error);
              break;
            }
          }
        }
      } else {
        error = Some(io::Error::other("managed buffer became shared"));
      }
      FileIoOutcome {
        file,
        buffer,
        bytes,
        error,
      }
    })
  }

  /// Writes the entire buffer in bounded chunks, unless an error occurs or
  /// cancellation is observed between system calls. Partial progress and the
  /// error are returned together.
  pub fn write(
    &self,
    file: OwnedFile,
    buffer: ManagedBuf,
  ) -> Result<Job<FileIoOutcome>, FsSubmissionError<(OwnedFile, ManagedBuf)>> {
    self.submit((file, buffer), |(mut file, buffer), token| {
      let mut bytes = 0;
      let mut error = None;
      while bytes < buffer.len() {
        if token.is_cancelled() {
          error = Some(io::Error::new(
            io::ErrorKind::Interrupted,
            "filesystem operation cancelled",
          ));
          break;
        }
        let end = buffer.len().min(bytes.saturating_add(IO_CHUNK));
        match file.file.write(&buffer[bytes..end]) {
          Ok(0) => {
            error = Some(io::Error::new(
              io::ErrorKind::WriteZero,
              "failed to write the complete managed buffer",
            ));
            break;
          }
          Ok(written) => bytes += written,
          Err(write_error) => {
            error = Some(write_error);
            break;
          }
        }
      }
      FileIoOutcome {
        file,
        buffer,
        bytes,
        error,
      }
    })
  }

  /// Reads at `offset` without changing the file's sequential cursor.
  #[cfg(unix)]
  pub fn read_at(
    &self,
    file: OwnedFile,
    mut buffer: ManagedBuf,
    offset: u64,
  ) -> Result<Job<FileIoOutcome>, FsSubmissionError<(OwnedFile, ManagedBuf, u64)>> {
    if buffer.get_mut().is_none() {
      return Err(FsSubmissionError {
        kind: FsSubmissionErrorKind::Resource(ResourceError::Shared),
        input: (file, buffer, offset),
      });
    }
    self.submit(
      (file, buffer, offset),
      |(file, mut buffer, offset), token| {
        let mut bytes: usize = 0;
        let mut error = None;
        if let Some(storage) = buffer.get_mut() {
          while bytes < storage.len() {
            if token.is_cancelled() {
              error = Some(io::Error::new(
                io::ErrorKind::Interrupted,
                "filesystem operation cancelled",
              ));
              break;
            }
            let end = storage.len().min(bytes.saturating_add(IO_CHUNK));
            let Some(position) = offset.checked_add(bytes as u64) else {
              error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file offset overflow",
              ));
              break;
            };
            match file.file.read_at(&mut storage[bytes..end], position) {
              Ok(0) => break,
              Ok(read) => bytes += read,
              Err(read_error) => {
                error = Some(read_error);
                break;
              }
            }
          }
        } else {
          error = Some(io::Error::other("managed buffer became shared"));
        }
        FileIoOutcome {
          file,
          buffer,
          bytes,
          error,
        }
      },
    )
  }

  /// Writes at `offset` without changing the file's sequential cursor.
  ///
  /// Linux ignores `offset` for a file opened with `append(true)` and appends
  /// instead, as specified by `std::os::unix::fs::FileExt::write_at`.
  #[cfg(unix)]
  pub fn write_at(
    &self,
    file: OwnedFile,
    buffer: ManagedBuf,
    offset: u64,
  ) -> Result<Job<FileIoOutcome>, FsSubmissionError<(OwnedFile, ManagedBuf, u64)>> {
    self.submit((file, buffer, offset), |(file, buffer, offset), token| {
      let mut bytes: usize = 0;
      let mut error = None;
      while bytes < buffer.len() {
        if token.is_cancelled() {
          error = Some(io::Error::new(
            io::ErrorKind::Interrupted,
            "filesystem operation cancelled",
          ));
          break;
        }
        let end = buffer.len().min(bytes.saturating_add(IO_CHUNK));
        let Some(position) = offset.checked_add(bytes as u64) else {
          error = Some(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file offset overflow",
          ));
          break;
        };
        match file.file.write_at(&buffer[bytes..end], position) {
          Ok(0) => {
            error = Some(io::Error::new(
              io::ErrorKind::WriteZero,
              "failed to write the complete managed buffer",
            ));
            break;
          }
          Ok(written) => bytes += written,
          Err(write_error) => {
            error = Some(write_error);
            break;
          }
        }
      }
      FileIoOutcome {
        file,
        buffer,
        bytes,
        error,
      }
    })
  }

  /// Flushes buffered file state and returns the owned file on either result.
  /// This forwards `std::fs::File::flush`; it does not synchronize storage or
  /// provide durability. Use [`Self::sync_all`] or [`Self::sync_data`] when
  /// synchronization is required.
  pub fn flush(
    &self,
    file: OwnedFile,
  ) -> Result<Job<(OwnedFile, io::Result<()>)>, FsSubmissionError<OwnedFile>> {
    self.submit(file, |mut file, _token| {
      let result = file.file.flush();
      (file, result)
    })
  }

  /// Synchronizes file contents and metadata through `File::sync_all`.
  /// The returned I/O result reflects the filesystem's synchronization call;
  /// it does not strengthen the platform's persistence guarantees.
  pub fn sync_all(
    &self,
    file: OwnedFile,
  ) -> Result<Job<(OwnedFile, io::Result<()>)>, FsSubmissionError<OwnedFile>> {
    self.submit(file, |file, _token| {
      let result = file.file.sync_all();
      (file, result)
    })
  }

  /// Synchronizes file data through `File::sync_data`, returning the file.
  pub fn sync_data(
    &self,
    file: OwnedFile,
  ) -> Result<Job<(OwnedFile, io::Result<()>)>, FsSubmissionError<OwnedFile>> {
    self.submit(file, |file, _token| {
      let result = file.file.sync_data();
      (file, result)
    })
  }

  /// Seeks the file and returns its new cursor position with the file.
  pub fn seek(
    &self,
    file: OwnedFile,
    position: SeekFrom,
  ) -> Result<Job<SeekOutcome>, FsSubmissionError<(OwnedFile, SeekFrom)>> {
    self.submit((file, position), |(mut file, position), _token| {
      let position = file.file.seek(position);
      SeekOutcome { file, position }
    })
  }

  /// Opens a directory for bounded, one-entry-at-a-time iteration.
  pub fn read_dir(
    &self,
    path: PathBuf,
  ) -> Result<Job<io::Result<Directory>>, FsSubmissionError<PathBuf>> {
    self.submit(path, |path, _token| {
      fs::read_dir(path).map(|entries| Directory { entries })
    })
  }

  /// Reads at most one directory entry and returns the iterator for reuse.
  pub fn next_entry(
    &self,
    directory: Directory,
  ) -> Result<Job<DirectoryEntryOutcome>, FsSubmissionError<Directory>> {
    self.submit(directory, |mut directory, _token| {
      let entry = match directory.entries.next() {
        Some(Ok(entry)) => Ok(Some(entry)),
        Some(Err(error)) => Err(error),
        None => Ok(None),
      };
      DirectoryEntryOutcome { directory, entry }
    })
  }

  /// Reads entry metadata on the pool under a disk permit, returning the entry.
  pub fn entry_metadata(
    &self,
    entry: fs::DirEntry,
  ) -> Result<Job<(fs::DirEntry, io::Result<Metadata>)>, FsSubmissionError<fs::DirEntry>> {
    self.submit(entry, |entry, _token| {
      let result = entry.metadata();
      (entry, result)
    })
  }

  /// Reads the entry's type on the pool, including filesystem fallback I/O.
  pub fn entry_file_type(
    &self,
    entry: fs::DirEntry,
  ) -> Result<Job<(fs::DirEntry, io::Result<fs::FileType>)>, FsSubmissionError<fs::DirEntry>> {
    self.submit(entry, |entry, _token| {
      let result = entry.file_type();
      (entry, result)
    })
  }

  /// Reads metadata for a path, following symbolic links.
  pub fn metadata(
    &self,
    path: PathBuf,
  ) -> Result<Job<io::Result<Metadata>>, FsSubmissionError<PathBuf>> {
    self.submit(path, |path, _token| fs::metadata(path))
  }

  /// Reads metadata for the path itself, without following a symbolic link.
  pub fn symlink_metadata(
    &self,
    path: PathBuf,
  ) -> Result<Job<io::Result<Metadata>>, FsSubmissionError<PathBuf>> {
    self.submit(path, |path, _token| fs::symlink_metadata(path))
  }

  /// Creates one directory.
  pub fn create_dir(
    &self,
    path: PathBuf,
  ) -> Result<Job<io::Result<()>>, FsSubmissionError<PathBuf>> {
    self.submit(path, |path, _token| fs::create_dir(path))
  }

  /// Removes one file.
  pub fn remove_file(
    &self,
    path: PathBuf,
  ) -> Result<Job<io::Result<()>>, FsSubmissionError<PathBuf>> {
    self.submit(path, |path, _token| fs::remove_file(path))
  }

  /// Renames a file or directory using the platform's `std::fs` semantics.
  pub fn rename(
    &self,
    from: PathBuf,
    to: PathBuf,
  ) -> Result<Job<io::Result<()>>, FsSubmissionError<(PathBuf, PathBuf)>> {
    self.submit((from, to), |(from, to), _token| fs::rename(from, to))
  }

  /// Reads the target of a symbolic link.
  pub fn read_link(
    &self,
    path: PathBuf,
  ) -> Result<Job<io::Result<PathBuf>>, FsSubmissionError<PathBuf>> {
    self.submit(path, |path, _token| fs::read_link(path))
  }

  fn submit<I, T>(
    &self,
    input: I,
    operation: impl FnOnce(I, CancellationToken) -> T + Send + 'static,
  ) -> Result<Job<T>, FsSubmissionError<I>>
  where
    I: Send + 'static,
    T: Send + 'static,
  {
    let permit = match self.scope.try_acquire(OperationRequest {
      disk: 1,
      network: 0,
    }) {
      Ok(permit) => permit,
      Err(error) => {
        return Err(FsSubmissionError {
          kind: FsSubmissionErrorKind::Resource(error),
          input,
        });
      }
    };
    let request = Arc::new(Mutex::new(Some(ReservedInput { input, permit })));
    let worker_request = Arc::clone(&request);
    match self.blocking.try_spawn(Resources::ZERO, move |token| {
      let ReservedInput { input, permit } = take_request(&worker_request);
      let result = operation(input, token);
      drop(permit);
      result
    }) {
      Ok(job) => {
        drop(request);
        Ok(job)
      }
      Err(error) => {
        let kind = error.kind;
        drop(error.job);
        let ReservedInput { input, permit } = take_request(&request);
        drop(permit);
        Err(FsSubmissionError {
          kind: FsSubmissionErrorKind::Runtime(kind),
          input,
        })
      }
    }
  }
}

struct ReservedInput<I> {
  // Field order keeps the permit alive through input destruction on queued
  // cancellation; Rust drops fields in declaration order.
  input: I,
  permit: OperationPermit,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn take_request<I>(request: &Mutex<Option<ReservedInput<I>>>) -> ReservedInput<I> {
  match lock(request).take() {
    Some(request) => request,
    None => panic!("filesystem request was consumed before its worker started"),
  }
}
