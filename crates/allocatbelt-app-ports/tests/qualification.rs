use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncError, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::fs::{FileIoOutcome, FsHandle, FsSubmissionErrorKind, OwnedFile};
use allocatbelt::runtime::managed::{
  OperationRequest, ResourceError, ResourceKind, ResourceLimits, ResourceScope,
};
use allocatbelt::runtime::process::{ProcessDriver, ProcessShutdownMode, SpawnErrorKind};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};
use allocatbelt::runtime::{
  Config as BlockingConfig, Resources, Runtime as BlockingRuntime, ShutdownMode, SubmitErrorKind,
};
use allocatbelt_app_ports::cpu::{self, CpuConfig};
use allocatbelt_app_ports::disk;
use allocatbelt_app_ports::http::{self, HttpConfig, MAX_REQUEST_BYTES};
use allocatbelt_app_ports::memory::{self, MemoryConfig};

static NEXT_TREE_ID: AtomicU64 = AtomicU64::new(1);

fn async_runtime(max_outstanding: usize) -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding,
    max_scopes: 2,
  })
  .expect("qualification runtime should start")
}

fn resources(memory: usize, disk: usize, network: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: memory,
    disk_concurrent_ops: disk,
    network_concurrent_ops: network,
  })
}

fn serial_cpu_digest(config: CpuConfig) -> u64 {
  (0..config.jobs).fold(config.seed, |digest, index| {
    let seed = config.seed ^ (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    digest.rotate_left(11) ^ cpu::kernel(seed, config.rounds) ^ index as u64
  })
}

#[test]
fn cpu_full_rejection_retries_the_same_job_after_owned_capacity_frees() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 3,
    max_scopes: 2,
  })
  .expect("single-worker CPU runtime should start");
  let ledger = resources(0, 0, 0);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("CPU scope should open");
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let gate = scope
    .spawn(async move {
      started_tx
        .send(())
        .expect("test keeps the gate notification receiver");
      release_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("test releases the async worker gate");
    })
    .expect("gate task should be admitted");
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("gate task should occupy the only async worker");
  let config = CpuConfig {
    jobs: 8,
    rounds: 8192,
    seed: 0x5a17,
  };

  let mut run = Box::pin(cpu::run(&scope, config));
  let first_poll = runtime
    .block_on(std::future::poll_fn(|cx| {
      Poll::Ready(run.as_mut().poll(cx))
    }))
    .expect("one manual CPU poll should complete");
  assert!(matches!(first_poll, Poll::Pending));
  assert_eq!(scope.snapshot().active_tasks, 3);
  release_tx
    .send(())
    .expect("async worker gate should still be held");
  let actual = runtime
    .block_on(run)
    .expect("root poll should complete")
    .expect("bounded CPU admission should recover from Full");
  assert_eq!(actual, serial_cpu_digest(config));
  runtime
    .block_on(gate)
    .expect("gate root poll should complete")
    .expect("gate task should finish");

  runtime
    .block_on(scope.close())
    .expect("CPU task cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("CPU runtime should stop");
}

#[test]
fn returned_managed_output_stays_charged_until_its_final_clone_drops() {
  let runtime = async_runtime(2);
  let ledger = resources(2 * 1024 * 1024, 0, 0);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("memory scope should open");
  let output = runtime
    .block_on(memory::run(&scope, ledger.clone(), MemoryConfig::default()))
    .expect("root poll should complete")
    .expect("memory port should complete");
  assert!(output.report.peak_replacement_was_enforced);
  assert_eq!(
    ledger.snapshot().managed_memory,
    output.report.charged_after_growth
  );
  assert_eq!(output.buffer.len(), MemoryConfig::default().grown_bytes);
  assert_eq!(
    output.report.checksum,
    allocatbelt_app_ports::memory::checksum(output.buffer.as_slice())
  );
  let last_owner = output.buffer.clone();
  drop(output);
  assert_eq!(
    ledger.snapshot().managed_memory,
    MemoryConfig::default().grown_bytes
  );
  drop(last_owner);
  assert_eq!(ledger.snapshot().managed_memory, 0);

  runtime
    .block_on(scope.close())
    .expect("memory scope cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("memory runtime should stop");
}

#[test]
fn http_preoccupied_network_capacity_rejects_and_releases_all_resources() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 3,
    max_waiters: 6,
  })
  .expect("reactor should start");
  let runtime = async_runtime(2);
  let ledger = resources(3 * MAX_REQUEST_BYTES + 512, 0, 1);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("HTTP scope should open");
  let occupied_network_slot = ledger
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .expect("test should hold the only network slot");

  let result = runtime
    .block_on(http::loopback_transaction(
      &scope,
      blocking.handle(),
      reactor.handle(),
      ledger.clone(),
      HttpConfig {
        body_bytes: 4096,
        seed: 0x6812,
      },
    ))
    .expect("HTTP root poll should complete");
  assert!(result.is_err(), "two endpoints must not exceed one permit");
  drop(occupied_network_slot);

  runtime
    .block_on(scope.close())
    .expect("HTTP scope cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("connect worker should drain");
  reactor.shutdown().expect("reactor should stop");
  let snapshot = ledger.snapshot();
  assert_eq!(snapshot.managed_memory, 0);
  assert_eq!(snapshot.network_ops, 0);
}

#[test]
fn http_endpoints_competing_for_idle_capacity_one_fail_and_clean_up() {
  let (completed_tx, completed_rx) = mpsc::sync_channel(1);
  let worker = thread::spawn(move || {
    let mut blocking = BlockingRuntime::new(BlockingConfig {
      workers: 1,
      max_outstanding: 4,
      capacity: Resources::ZERO,
    })
    .expect("blocking runtime should start");
    let reactor = Reactor::new(ReactorConfig {
      max_registrations: 3,
      max_waiters: 6,
    })
    .expect("reactor should start");
    let runtime = async_runtime(2);
    let ledger = resources(3 * MAX_REQUEST_BYTES + 512, 0, 1);
    let scope = runtime
      .scope_with_resources(&ledger)
      .expect("HTTP scope should open");

    let result = runtime
      .block_on(http::loopback_transaction(
        &scope,
        blocking.handle(),
        reactor.handle(),
        ledger.clone(),
        HttpConfig {
          body_bytes: 4096,
          seed: 0x7b21,
        },
      ))
      .expect("HTTP root poll should complete");
    assert!(
      result.is_err(),
      "two live endpoints must contend for one slot"
    );

    runtime
      .block_on(scope.close())
      .expect("HTTP scope cleanup should finish");
    runtime
      .shutdown(AsyncShutdown::Drain)
      .expect("async runtime should stop");
    blocking
      .shutdown(ShutdownMode::Drain)
      .expect("connect worker should drain");
    reactor.shutdown().expect("reactor should stop");
    completed_tx
      .send(ledger.snapshot())
      .expect("test should receive the cleaned resource snapshot");
  });

  let snapshot = completed_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("capacity-one HTTP transaction and cleanup should finish");
  worker
    .join()
    .expect("capacity-one HTTP qualification thread should not panic");
  assert_eq!(snapshot.managed_memory, 0);
  assert_eq!(snapshot.network_ops, 0);
}

#[test]
fn dropping_http_transaction_aborts_server_and_releases_scope_slot() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let blocking_handle = blocking.handle();
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = blocking_handle
    .try_spawn(Resources::ZERO, move |_| {
      started_tx
        .send(())
        .expect("test keeps the gate notification receiver");
      release_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("test releases the worker gate");
    })
    .expect("gate job should be admitted");
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("gate job should occupy the blocking worker");

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 3,
    max_waiters: 6,
  })
  .expect("reactor should start");
  let runtime = async_runtime(1);
  let ledger = resources(3 * MAX_REQUEST_BYTES + 512, 0, 2);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("HTTP scope should open");

  let mut transaction = Box::pin(http::loopback_transaction(
    &scope,
    blocking_handle,
    reactor.handle(),
    ledger.clone(),
    HttpConfig {
      body_bytes: 1024,
      seed: 0x9137,
    },
  ));
  let first_poll = runtime
    .block_on(std::future::poll_fn(|cx| {
      Poll::Ready(transaction.as_mut().poll(cx))
    }))
    .expect("one manual transaction poll should complete");
  assert!(matches!(first_poll, Poll::Pending));
  drop(transaction);

  // The scope has capacity for one task. The server initially owns it; a
  // successful sentinel admission proves the outer-future Drop guard aborted
  // and completed that server task instead of merely detaching its join.
  let deadline = Instant::now() + Duration::from_secs(5);
  let sentinel = loop {
    match scope.spawn(async { 0x51u8 }) {
      Ok(job) => break job,
      Err(error) if error.kind == AsyncError::Full => {
        drop(error.into_future());
        assert!(
          Instant::now() < deadline,
          "aborted HTTP server kept its slot"
        );
        thread::yield_now();
      }
      Err(error) => panic!("sentinel admission failed unexpectedly: {}", error.kind),
    }
  };
  assert_eq!(
    runtime
      .block_on(sentinel)
      .expect("sentinel root poll should complete")
      .expect("sentinel task should join"),
    0x51
  );

  release_tx
    .send(())
    .expect("blocking worker gate should still be held");
  blocker.join().expect("gate job should finish");
  runtime
    .block_on(scope.close())
    .expect("HTTP task cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("queued connect should drain");
  reactor.shutdown().expect("reactor should stop");
  let snapshot = ledger.snapshot();
  assert_eq!(snapshot.managed_memory, 0);
  assert_eq!(snapshot.network_ops, 0);
}

struct TestTree(PathBuf);

impl TestTree {
  fn new() -> Self {
    let id = NEXT_TREE_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-port-qualification-{}-{id}",
      std::process::id()
    ));
    fs::create_dir(&path).expect("unique qualification directory should be created");
    Self(path)
  }

  fn payload_path(&self) -> PathBuf {
    self.0.join("payload.bin")
  }

  fn create_payload(&self) -> File {
    OpenOptions::new()
      .read(true)
      .write(true)
      .create_new(true)
      .open(self.payload_path())
      .expect("payload file should be created once")
  }
}

impl Drop for TestTree {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.0);
  }
}

#[test]
fn filesystem_open_rejection_recovers_path_and_options_for_retry() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let handle = blocking.handle();
  let ledger = resources(0, 1, 0);
  let fs_handle = FsHandle::new(handle.clone(), ledger.clone());
  let tree = TestTree::new();
  drop(tree.create_payload());
  let path = tree.payload_path();
  let mut options = OpenOptions::new();
  options.read(true).write(true);

  let permit = ledger
    .try_acquire(OperationRequest {
      disk: 1,
      network: 0,
    })
    .expect("test should hold the only disk permit");
  let (path, options) = match disk::submit_prepared_open(&fs_handle, path, options) {
    Ok(_) => panic!("disk quota should reject the prepared open"),
    Err(error) => {
      assert!(matches!(
        error.kind,
        FsSubmissionErrorKind::Resource(ResourceError::Exhausted(ResourceKind::Disk))
      ));
      error.into_input()
    }
  };
  assert_eq!(path, tree.payload_path());
  drop(permit);

  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = handle
    .try_spawn(Resources::ZERO, move |_| {
      started_tx
        .send(())
        .expect("test keeps the gate notification receiver");
      release_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("test releases the blocking worker");
    })
    .expect("gate job should occupy the only blocking slot");
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("gate job should be running");
  let (path, options) = match disk::submit_prepared_open(&fs_handle, path, options) {
    Ok(_) => panic!("blocking-pool capacity should reject the open"),
    Err(error) => {
      assert!(matches!(
        error.kind,
        FsSubmissionErrorKind::Runtime(SubmitErrorKind::Full)
      ));
      error.into_input()
    }
  };
  assert_eq!(path, tree.payload_path());
  assert_eq!(ledger.snapshot().disk_ops, 0);
  release_tx
    .send(())
    .expect("blocking worker gate should still be held");
  blocker.join().expect("gate job should finish");

  let opened = disk::submit_prepared_open(&fs_handle, path, options)
    .expect("recovered path and options should be admitted")
    .join()
    .expect("prepared open should finish")
    .expect("prepared file should open");
  drop(opened);
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  assert_eq!(ledger.snapshot().disk_ops, 0);
}

#[test]
fn filesystem_rejection_recovers_the_same_file_buffer_and_offset() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let handle = blocking.handle();
  let ledger = resources(8192, 1, 0);
  let fs_handle = FsHandle::new(handle.clone(), ledger.clone());
  let tree = TestTree::new();
  let std_file = tree.create_payload();
  let fd = std_file.as_raw_fd();
  let file = OwnedFile::from_std(std_file);
  let mut buffer = ledger
    .try_alloc_zeroed(4096)
    .expect("managed write buffer should fit");
  for (index, byte) in buffer
    .get_mut()
    .expect("unique buffer should be writable")
    .iter_mut()
    .enumerate()
  {
    *byte = (index.wrapping_mul(37) ^ 0xa5) as u8;
  }
  let buffer_address = buffer.as_slice().as_ptr();
  let expected_checksum = allocatbelt_app_ports::memory::checksum(buffer.as_slice());
  let offset = 73u64;

  let permit = ledger
    .try_acquire(OperationRequest {
      disk: 1,
      network: 0,
    })
    .expect("test should hold the sole disk permit");
  let (file, buffer, recovered_offset) =
    match disk::submit_positional_write(&fs_handle, file, buffer, offset) {
      Ok(_) => panic!("disk quota should reject the first write"),
      Err(error) => {
        assert!(matches!(
          error.kind,
          FsSubmissionErrorKind::Resource(ResourceError::Exhausted(ResourceKind::Disk))
        ));
        error.into_input()
      }
    };
  drop(permit);

  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = handle
    .try_spawn(Resources::ZERO, move |_| {
      started_tx
        .send(())
        .expect("test keeps the gate notification receiver");
      release_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("test releases the blocking worker");
    })
    .expect("gate job should occupy the only blocking slot");
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("gate job should be running");
  let buffer_address_after_quota_rejection = buffer.as_slice().as_ptr();
  let (file, buffer, recovered_offset) =
    match disk::submit_positional_write(&fs_handle, file, buffer, recovered_offset) {
      Ok(_) => panic!("blocking-pool capacity should reject the write"),
      Err(error) => {
        assert!(matches!(
          error.kind,
          FsSubmissionErrorKind::Runtime(SubmitErrorKind::Full)
        ));
        error.into_input()
      }
    };
  let std_file = file.into_std();
  assert_eq!(std_file.as_raw_fd(), fd);
  let file = OwnedFile::from_std(std_file);
  assert_eq!(buffer.as_slice().as_ptr(), buffer_address);
  assert_eq!(buffer_address_after_quota_rejection, buffer_address);
  assert_eq!(recovered_offset, offset);
  assert_eq!(ledger.snapshot().disk_ops, 0);
  assert_eq!(ledger.snapshot().managed_memory, 4096);

  release_tx
    .send(())
    .expect("blocking worker gate should still be held");
  blocker.join().expect("gate job should finish");
  let outcome: FileIoOutcome =
    disk::submit_positional_write(&fs_handle, file, buffer, recovered_offset)
      .expect("same owned inputs should be admitted after capacity returns")
      .join()
      .expect("positional write should finish");
  assert_eq!(outcome.bytes, 4096);
  assert!(outcome.error.is_none());
  assert_eq!(
    allocatbelt_app_ports::memory::checksum(outcome.buffer.as_slice()),
    expected_checksum
  );
  drop(outcome);
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  assert_eq!(ledger.snapshot().managed_memory, 0);
  assert_eq!(ledger.snapshot().disk_ops, 0);
}

#[test]
fn detached_multichunk_write_keeps_buffer_and_disk_permit_until_worker_finishes() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let handle = blocking.handle();
  let bytes = 3 * 64 * 1024 + 17;
  let ledger = resources(bytes, 1, 0);
  let fs_handle = FsHandle::new(handle.clone(), ledger.clone());
  let tree = TestTree::new();
  let path = tree.payload_path();
  let file = OwnedFile::from_std(tree.create_payload());
  let mut buffer = ledger
    .try_alloc_zeroed(bytes)
    .expect("managed payload should fit");
  for (index, byte) in buffer
    .get_mut()
    .expect("unique buffer should be writable")
    .iter_mut()
    .enumerate()
  {
    *byte = (index.wrapping_mul(19).wrapping_add(index >> 7) ^ 0xd3) as u8;
  }
  let expected = allocatbelt_app_ports::memory::checksum(buffer.as_slice());

  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = handle
    .try_spawn(Resources::ZERO, move |_| {
      started_tx
        .send(())
        .expect("test keeps the gate notification receiver");
      release_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("test releases the blocking worker");
    })
    .expect("gate job should be admitted");
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("gate job should occupy the worker");

  let write = fs_handle
    .write_at(file, buffer, 211)
    .expect("queued positional write should be admitted");
  assert_eq!(ledger.snapshot().disk_ops, 1);
  assert_eq!(ledger.snapshot().managed_memory, bytes);
  drop(write); // Job drop detaches; it does not cancel or release its inputs.
  assert_eq!(ledger.snapshot().disk_ops, 1);
  assert_eq!(ledger.snapshot().managed_memory, bytes);

  release_tx
    .send(())
    .expect("blocking worker gate should still be held");
  blocker.join().expect("gate job should finish");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("queued positional write should finish before shutdown");
  assert_eq!(ledger.snapshot().disk_ops, 0);
  assert_eq!(ledger.snapshot().managed_memory, 0);

  let mut file = File::open(path).expect("written file should remain available");
  let mut actual = vec![0; 211 + bytes];
  file
    .seek(SeekFrom::Start(211))
    .expect("readback should use the same explicit file offset");
  file
    .read_exact(&mut actual[211..])
    .expect("detached multi-chunk write should finish");
  assert_eq!(
    allocatbelt_app_ports::memory::checksum(&actual[211..]),
    expected
  );
}

#[test]
fn process_driver_recovers_full_command_after_child_is_reaped_and_shuts_down() {
  let mut driver = ProcessDriver::new(1).expect("one-child process driver should start");
  let runtime = async_runtime(2);
  let mut child = driver
    .spawn({
      let mut command = Command::new("/bin/sh");
      command.arg("-c").arg("exec sleep 30");
      command
    })
    .expect("first child should occupy the only slot");
  child.set_kill_on_drop(true);

  let mut rejected_command = Command::new("/bin/true");
  rejected_command.arg("retained-until-retry");
  let (command, kind) = match driver.spawn(rejected_command) {
    Ok(_) => panic!("unreaped child should retain the only process slot"),
    Err(error) => error.into_parts(),
  };
  assert!(matches!(kind, SpawnErrorKind::Full));
  assert_eq!(command.get_program(), "/bin/true");
  assert_eq!(
    command.get_args().collect::<Vec<_>>(),
    vec![std::ffi::OsStr::new("retained-until-retry")]
  );
  assert_eq!(driver.active_children(), 1);

  let status = runtime
    .block_on(child.kill_and_wait())
    .expect("wait root poll should complete")
    .expect("child kill and actual reap should complete");
  assert!(!status.success());
  assert_eq!(driver.active_children(), 0);

  let mut retried = driver
    .spawn(command)
    .expect("recovered command should be admitted after the first child is reaped");
  let status = runtime
    .block_on(retried.wait())
    .expect("wait root poll should complete")
    .expect("retried child should be reaped");
  assert!(status.success());

  let mut live = driver
    .spawn({
      let mut command = Command::new("/bin/sh");
      command.arg("-c").arg("exec sleep 30");
      command
    })
    .expect("driver should admit one final live child");
  live.set_kill_on_drop(true);
  assert_eq!(driver.active_children(), 1);
  driver
    .shutdown(ProcessShutdownMode::KillAndWait)
    .expect("KillAndWait should stop admission and reap the live child");
  assert_eq!(driver.active_children(), 0);
  let status = runtime
    .block_on(live.wait())
    .expect("wait root poll should complete")
    .expect("killed child completion should remain observable");
  assert!(!status.success());
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("wait executor should stop");
}
