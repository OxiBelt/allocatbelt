use super::*;
use crate::runtime::byte_rate::ByteRateConfig;
use crate::runtime::job::Control;
use crate::runtime::worker::Ident;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

fn bucket(burst: usize) -> ByteRateLimit {
  ByteRateLimit::new(ByteRateConfig {
    bytes_per_second: 1,
    burst_bytes: burst,
    max_reservations: 4,
  })
  .unwrap()
}

fn token() -> (Arc<Control>, CancellationToken) {
  let control = Control::new(Ident::new(987), None);
  let token = CancellationToken::new(control.clone());
  (control, token)
}

fn configured(bucket: &ByteRateLimit) -> FsRateControl {
  FsRateControl::new(
    bucket,
    None,
    #[cfg(feature = "resource-feedback")]
    None,
  )
  .unwrap()
}

#[test]
fn partial_completion_refunds_only_unused_credit_and_error_refunds_all() {
  let bucket = bucket(8);
  let rate = configured(&bucket);
  let (_, token) = token();
  assert_eq!(
    limited_io(Some(&rate), 30, &token, |offered| {
      assert_eq!(offered, 8);
      assert_eq!(bucket.snapshot().reserved_bytes, 8);
      Ok(3)
    })
    .unwrap(),
    3
  );
  assert_eq!(bucket.snapshot().available_bytes, 5);
  assert_eq!(bucket.snapshot().reserved_bytes, 0);
  assert!(
    limited_io(Some(&rate), 5, &token, |_| {
      Err(io::ErrorKind::PermissionDenied.into())
    })
    .is_err()
  );
  assert_eq!(bucket.snapshot().available_bytes, 5);
}

#[test]
fn invalid_completion_spends_offer_instead_of_minting_credit() {
  let bucket = bucket(8);
  let rate = configured(&bucket);
  let (_, token) = token();
  let error = limited_io(Some(&rate), 4, &token, |_| Ok(5)).unwrap_err();
  assert_eq!(error.kind(), io::ErrorKind::InvalidData);
  assert_eq!(bucket.snapshot().available_bytes, 4);
  assert_eq!(bucket.snapshot().reserved_bytes, 0);
}

#[test]
fn cancellation_while_waiting_never_calls_the_endpoint() {
  let bucket = bucket(1);
  bucket.try_reserve(1).unwrap().commit(1).unwrap();
  let rate = configured(&bucket);
  let (control, token) = token();
  let called = Arc::new(AtomicBool::new(false));
  let worker_called = called.clone();
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let (done_tx, done_rx) = mpsc::channel();
  let worker = std::thread::spawn(move || {
    let outcome = limited_io_with_wait(
      Some(&rate),
      1,
      &token,
      |_| {
        worker_called.store(true, Ordering::Relaxed);
        Ok(1)
      },
      |wait| {
        assert!(wait <= Duration::from_millis(10));
        // Witness an actual empty-bucket wait, then let cancellation win
        // before the next admission attempt instead of relying on a sleep.
        started_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
      },
    );
    done_tx.send(outcome.map_err(|error| error.kind())).unwrap();
  });
  started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
  control.mark_cancelled();
  release_tx.send(()).unwrap();
  assert_eq!(
    done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
    Err(io::ErrorKind::Interrupted)
  );
  worker.join().unwrap();
  assert!(!called.load(Ordering::Relaxed));
  assert_eq!(bucket.snapshot().reservations, 0);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn clone_owner_keeps_meter_registered_and_records_only_committed_bytes() {
  let bucket = bucket(8);
  let meter = IoFeedbackMeter::new();
  let rate = FsRateControl::new(&bucket, None, Some(&meter)).unwrap();
  let retained = rate.clone();
  drop(rate);
  assert_eq!(meter.snapshot().attached_sources, 1);
  let (_, token) = token();
  limited_io(Some(&retained), 8, &token, |_| Ok(3)).unwrap();
  limited_io(Some(&retained), 3, &token, |_| Ok(0)).unwrap();
  assert_eq!(meter.snapshot().committed_bytes, 3);
  assert_eq!(meter.snapshot().completions, 1);
  drop(retained);
  assert_eq!(meter.snapshot().attached_sources, 0);
}

#[test]
fn actual_file_read_and_positional_write_use_the_configured_bucket() {
  use crate::runtime::fs::{FsHandle, OwnedFile};
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::{Config, Resources, Runtime, ShutdownMode};
  use std::fs::OpenOptions;
  use std::io::{Seek, SeekFrom};

  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 64,
    disk_concurrent_ops: 1,
    network_concurrent_ops: 0,
  });
  let bucket = bucket(32);
  let handle = FsHandle::new(runtime.handle(), scope.clone())
    .with_byte_rate(&bucket)
    .unwrap();
  let path = std::env::temp_dir().join(format!("allocatbelt-fs-rate-{}", std::process::id()));
  let standard = OpenOptions::new()
    .create_new(true)
    .read(true)
    .write(true)
    .open(&path)
    .unwrap();
  std::fs::remove_file(&path).unwrap();
  let file = OwnedFile::from_std(standard);
  let mut buffer = scope.try_alloc_zeroed(8).unwrap();
  buffer.get_mut().unwrap().copy_from_slice(b"abcdefgh");
  let outcome = handle.write_at(file, buffer, 2).unwrap().join().unwrap();
  assert!(outcome.error.is_none());
  assert_eq!(outcome.bytes, 8);
  let mut standard = outcome.file.into_std();
  assert_eq!(standard.stream_position().unwrap(), 0);
  standard.seek(SeekFrom::Start(2)).unwrap();
  let outcome = handle
    .read(OwnedFile::from_std(standard), outcome.buffer)
    .unwrap()
    .join()
    .unwrap();
  assert!(outcome.error.is_none());
  assert_eq!(outcome.bytes, 8);
  assert_eq!(outcome.buffer.as_slice(), b"abcdefgh");
  assert_eq!(bucket.snapshot().available_bytes, 16);
  let mut buffer = outcome.buffer;
  buffer.get_mut().unwrap().copy_from_slice(b"ijklmnop");
  let outcome = handle.write(outcome.file, buffer).unwrap().join().unwrap();
  assert!(outcome.error.is_none());
  assert_eq!(outcome.bytes, 8);
  let mut outcome = handle
    .read_at(outcome.file, outcome.buffer, 10)
    .unwrap()
    .join()
    .unwrap();
  assert!(outcome.error.is_none());
  assert_eq!(outcome.bytes, 8);
  assert_eq!(outcome.buffer.as_slice(), b"ijklmnop");
  assert_eq!(outcome.file.file.stream_position().unwrap(), 18);
  assert_eq!(bucket.snapshot().available_bytes, 0);
  assert_eq!(scope.snapshot().disk_ops, 0);
  assert!(scope.snapshot().managed_memory > 0);
  drop(outcome);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn configured_copy_charges_both_directions_and_recovers_memory_refusal() {
  use crate::runtime::fs::{FsHandle, FsSubmissionErrorKind};
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::{Config, Resources, Runtime, ShutdownMode};
  use std::os::unix::fs::PermissionsExt;

  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 4,
    disk_concurrent_ops: 1,
    network_concurrent_ops: 0,
  });
  let bucket = bucket(32);
  let handle = FsHandle::new(runtime.handle(), scope.clone())
    .with_byte_rate(&bucket)
    .unwrap();
  let base = std::env::temp_dir().join(format!("allocatbelt-fs-rate-copy-{}", std::process::id()));
  std::fs::create_dir(&base).unwrap();
  let source = base.join("source");
  let destination = base.join("destination");
  std::fs::write(&source, b"abcdefgh").unwrap();
  std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
  std::fs::write(&destination, b"old longer destination").unwrap();
  let copied = handle
    .copy(source.clone(), destination.clone())
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(copied, 8);
  assert_eq!(std::fs::read(&destination).unwrap(), b"abcdefgh");
  assert_eq!(
    std::fs::metadata(&destination)
      .unwrap()
      .permissions()
      .mode()
      & 0o777,
    0o640
  );
  assert_eq!(bucket.snapshot().available_bytes, 16);
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(scope.snapshot().disk_ops, 0);

  let no_memory = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 1,
    network_concurrent_ops: 0,
  });
  let handle = FsHandle::new(runtime.handle(), no_memory.clone())
    .with_byte_rate(&bucket)
    .unwrap();
  let error = handle
    .copy(source.clone(), destination.clone())
    .unwrap_err();
  assert!(matches!(error.kind, FsSubmissionErrorKind::Resource(_)));
  assert_eq!(error.input, (source.clone(), destination.clone()));
  assert_eq!(no_memory.snapshot().disk_ops, 0);
  assert_eq!(std::fs::read(&destination).unwrap(), b"abcdefgh");
  assert_eq!(bucket.snapshot().available_bytes, 16);
  std::fs::remove_file(source).unwrap();
  std::fs::remove_file(destination).unwrap();
  std::fs::remove_dir(base).unwrap();
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn destination_creation_never_adds_permissions_before_chmod() {
  use std::os::unix::fs::PermissionsExt;
  let path = std::env::temp_dir().join(format!("allocatbelt-fs-rate-mode-{}", std::process::id()));
  let destination = open_copy_destination(&path, &std::fs::Permissions::from_mode(0o600)).unwrap();
  // Inspect immediately after creation, before the copy's regular-file chmod.
  assert_eq!(
    destination.metadata().unwrap().permissions().mode() & 0o077,
    0
  );
  drop(destination);
  std::fs::remove_file(path).unwrap();
}

#[cfg(unix)]
#[test]
fn source_symlink_copy_preserves_existing_fifo_permissions() {
  use std::io::Read;
  use std::os::unix::fs::{PermissionsExt, symlink};
  let base = std::env::temp_dir().join(format!("allocatbelt-fs-rate-fifo-{}", std::process::id()));
  std::fs::create_dir(&base).unwrap();
  let source = base.join("source");
  let alias = base.join("alias");
  let destination = base.join("fifo");
  std::fs::write(&source, b"abc").unwrap();
  std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
  symlink(&source, &alias).unwrap();
  rustix::fs::mkfifoat(
    rustix::fs::CWD,
    &destination,
    rustix::fs::Mode::from_raw_mode(0o600),
  )
  .unwrap();
  let mut receiver = std::fs::OpenOptions::new()
    .read(true)
    .write(true)
    .open(&destination)
    .unwrap();
  let bucket = bucket(32);
  let rate = configured(&bucket);
  let (_, token) = token();
  let mut scratch = [0; 2];
  assert_eq!(
    copy_file(&alias, &destination, &mut scratch, &rate, &token).unwrap(),
    3
  );
  let mut received = [0; 3];
  receiver.read_exact(&mut received).unwrap();
  assert_eq!(&received, b"abc");
  assert_eq!(
    std::fs::metadata(&destination)
      .unwrap()
      .permissions()
      .mode()
      & 0o777,
    0o600
  );
  assert_eq!(bucket.snapshot().available_bytes, 26);
  drop(receiver);
  std::fs::remove_file(alias).unwrap();
  std::fs::remove_file(source).unwrap();
  std::fs::remove_file(destination).unwrap();
  std::fs::remove_dir(base).unwrap();
}

#[test]
fn public_blocking_adapter_commits_real_file_prefix_and_recovers_cancelled_entry() {
  use std::os::unix::fs::FileExt;
  let bucket = bucket(8);
  let adapter = BlockingByteIo::new(&bucket, None).unwrap();
  let path = std::env::temp_dir().join(format!(
    "allocatbelt-blocking-byte-prefix-{}",
    std::process::id()
  ));
  let file = std::fs::OpenOptions::new()
    .read(true)
    .write(true)
    .create_new(true)
    .open(&path)
    .unwrap();
  std::fs::remove_file(&path).unwrap();
  assert_eq!(
    adapter
      .run(
        8,
        || false,
        |offered| {
          assert_eq!(offered, 8);
          file.write_at(&b"abc"[..], 0)
        }
      )
      .unwrap(),
    3
  );
  assert_eq!(bucket.snapshot().reserved_bytes, 0);
  let error = adapter
    .run(5, || true, |_| panic!("cancelled endpoint must not run"))
    .unwrap_err();
  assert_eq!(error.kind(), io::ErrorKind::Interrupted);
  let mut output = [0; 3];
  assert_eq!(file.read_at(&mut output, 0).unwrap(), 3);
  assert_eq!(&output, b"abc");
}

#[test]
fn public_blocking_adapter_waits_for_credit_then_observes_cancellation() {
  let bucket = bucket(1);
  bucket.try_reserve(1).unwrap().commit(1).unwrap();
  let adapter = BlockingByteIo::new(&bucket, None).unwrap();
  let cancelled = Arc::new(AtomicBool::new(false));
  let stop = cancelled.clone();
  let (waited_tx, waited_rx) = mpsc::channel();
  let worker = std::thread::spawn(move || {
    let mut checks = 0;
    adapter.run(
      1,
      || {
        checks += 1;
        // The first admission failed against the empty bucket, so this second
        // check happens after the actual credit-wait branch has slept.
        if checks == 2 {
          waited_tx.send(()).unwrap();
        }
        stop.load(Ordering::Acquire)
      },
      |_| panic!("cancelled empty-bucket endpoint must not run"),
    )
  });
  waited_rx.recv_timeout(Duration::from_secs(3)).unwrap();
  cancelled.store(true, Ordering::Release);
  assert_eq!(
    worker.join().unwrap().unwrap_err().kind(),
    io::ErrorKind::Interrupted
  );
  assert_eq!(bucket.snapshot().reserved_bytes, 0);
}

#[test]
fn panicking_byte_operation_spends_unknown_offer_and_invalidates_telemetry() {
  let bucket = bucket(8);
  #[cfg(feature = "resource-feedback")]
  let meter = IoFeedbackMeter::new();
  let adapter = {
    #[cfg(feature = "resource-feedback")]
    {
      BlockingByteIo::new_metered(&bucket, None, &meter).unwrap()
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      BlockingByteIo::new(&bucket, None).unwrap()
    }
  };
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let _ = adapter.run(
      8,
      || false,
      |_| -> io::Result<usize> { panic!("unknown I/O completion") },
    );
  }));
  assert!(result.is_err());
  assert_eq!(bucket.snapshot().reserved_bytes, 0);
  assert_eq!(bucket.snapshot().available_bytes, 0);
  #[cfg(feature = "resource-feedback")]
  {
    assert!(meter.snapshot().diagnostics.invalid_io);
    assert_eq!(meter.snapshot().committed_bytes, 0);
    assert_eq!(meter.snapshot().completions, 0);
  }
}

#[test]
fn normal_io_error_refunds_during_an_unrelated_outer_unwind() {
  use std::sync::atomic::AtomicUsize;
  let bucket = bucket(8);
  let adapter = BlockingByteIo::new(&bucket, None).unwrap();
  let observed = AtomicUsize::new(usize::MAX);
  struct ErrorOnDrop<'a> {
    adapter: &'a BlockingByteIo,
    bucket: &'a ByteRateLimit,
    observed: &'a AtomicUsize,
  }
  impl Drop for ErrorOnDrop<'_> {
    fn drop(&mut self) {
      let _ = self
        .adapter
        .run(8, || false, |_| Err(io::ErrorKind::PermissionDenied.into()));
      self
        .observed
        .store(self.bucket.snapshot().available_bytes, Ordering::Release);
    }
  }
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let _drop = ErrorOnDrop {
      adapter: &adapter,
      bucket: &bucket,
      observed: &observed,
    };
    panic!("unrelated outer unwind");
  }));
  assert!(result.is_err());
  assert_eq!(observed.load(Ordering::Acquire), 8);
  assert_eq!(bucket.snapshot().reserved_bytes, 0);
}
