//! Streaming files with finite byte budgets and sticky write failures.
//!
//! `create_new` atomically refuses an existing final component, including a
//! symlink or special file. Callers must supply an absolute path inside their
//! private output directory: this helper does not secure ancestor directories.
//! Completion checks the descriptor and pathname identity, but the independent
//! reader must still hash and validate the artifact after the process exits.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) struct TraceFile {
  file: File,
  path: PathBuf,
  identity: (u64, u64),
  limit: u64,
  written: u64,
  failure: Option<ErrorKind>,
}

impl TraceFile {
  pub(crate) fn create(path: &Path, limit: u64) -> io::Result<Self> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
      return Err(io::Error::new(
        ErrorKind::InvalidInput,
        "invalid trace file path",
      ));
    }
    let file = OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(0o600)
      .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() != 0 {
      return Err(io::Error::other(
        "trace descriptor is not a fresh private regular file",
      ));
    }
    let writer = Self {
      file,
      path: path.to_owned(),
      identity: (metadata.dev(), metadata.ino()),
      limit,
      written: 0,
      failure: None,
    };
    writer.verify_identity()?;
    Ok(writer)
  }

  fn check_failure(&self) -> io::Result<()> {
    if let Some(kind) = self.failure {
      Err(io::Error::new(kind, "trace writer previously failed"))
    } else {
      Ok(())
    }
  }

  fn retain_failure<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
    if let Err(error) = &result {
      self.failure.get_or_insert(error.kind());
    }
    result
  }

  fn verify_identity(&self) -> io::Result<()> {
    let descriptor = self.file.metadata()?;
    let path = fs::symlink_metadata(&self.path)?;
    if !descriptor.is_file()
      || !path.is_file()
      || descriptor.nlink() != 1
      || descriptor.mode() & 0o077 != 0
      || path.mode() & 0o077 != 0
      || (descriptor.dev(), descriptor.ino()) != self.identity
      || (path.dev(), path.ino()) != self.identity
      || descriptor.len() != self.written
      || path.len() != self.written
    {
      return Err(io::Error::other(
        "trace file identity, permissions or length changed",
      ));
    }
    Ok(())
  }

  /// Syncs only a successful writer; failed files remain as failure evidence.
  pub(crate) fn finish(mut self) -> io::Result<u64> {
    self.flush()?;
    let result = self.file.sync_all().and_then(|()| self.verify_identity());
    self.retain_failure(result)?;
    Ok(self.written)
  }
}

impl Write for TraceFile {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    self.check_failure()?;
    if self
      .written
      .checked_add(bytes.len() as u64)
      .is_none_or(|next| next > self.limit)
    {
      return self.retain_failure(Err(io::Error::new(
        ErrorKind::FileTooLarge,
        "trace byte budget exceeded",
      )));
    }
    if bytes.is_empty() {
      return Ok(0);
    }
    loop {
      match self.file.write(bytes) {
        Err(error) if error.kind() == ErrorKind::Interrupted => continue,
        Ok(0) => {
          return self.retain_failure(Err(io::Error::new(
            ErrorKind::WriteZero,
            "trace file accepted no bytes",
          )));
        }
        Ok(count) => {
          self.written += count as u64;
          return Ok(count);
        }
        Err(error) => return self.retain_failure(Err(error)),
      }
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    self.check_failure()?;
    let result = self.file.flush();
    self.retain_failure(result)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicUsize, Ordering};

  static NEXT: AtomicUsize = AtomicUsize::new(0);

  struct Fixture(PathBuf);

  impl Fixture {
    fn new() -> Self {
      let path = std::env::temp_dir().join(format!(
        "trace-writer-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
      ));
      fs::create_dir(&path).unwrap();
      Self(path)
    }
    fn file(&self) -> PathBuf {
      self.0.join("trace.tsv")
    }
  }

  impl Drop for Fixture {
    fn drop(&mut self) {
      fs::remove_dir_all(&self.0).unwrap();
    }
  }

  #[test]
  fn exact_limit_finishes_and_refused_slice_leaves_no_prefix() {
    let fixture = Fixture::new();
    let mut writer = TraceFile::create(&fixture.file(), 3).unwrap();
    writer.write_all(b"abc").unwrap();
    assert_eq!(writer.finish().unwrap(), 3);
    assert_eq!(fs::read(fixture.file()).unwrap(), b"abc");
    let second = fixture.0.join("second.tsv");
    let mut writer = TraceFile::create(&second, 3).unwrap();
    writer.write_all(b"a").unwrap();
    assert_eq!(
      writer.write(b"bcd").unwrap_err().kind(),
      ErrorKind::FileTooLarge
    );
    assert_eq!(
      writer.write(b"b").unwrap_err().kind(),
      ErrorKind::FileTooLarge
    );
    assert!(writer.finish().is_err());
    assert_eq!(fs::read(second).unwrap(), b"a");
  }

  #[test]
  fn existing_file_symlink_and_path_replacement_are_refused() {
    let fixture = Fixture::new();
    let path = fixture.file();
    let mut writer = TraceFile::create(&path, 4).unwrap();
    assert!(TraceFile::create(&path, 4).is_err());
    writer.write_all(b"good").unwrap();
    fs::rename(&path, fixture.0.join("original.tsv")).unwrap();
    fs::write(&path, b"fake").unwrap();
    assert!(writer.finish().is_err());
    assert_eq!(fs::read(path).unwrap(), b"fake");
    let link = fixture.0.join("link.tsv");
    std::os::unix::fs::symlink(fixture.0.join("missing"), &link).unwrap();
    assert!(TraceFile::create(&link, 4).is_err());
  }
}
