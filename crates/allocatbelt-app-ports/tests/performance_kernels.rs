use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::fs::FsHandle;
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::{
  Config as BlockingConfig, Resources, Runtime as BlockingRuntime, ShutdownMode,
};
use allocatbelt_app_ports::disk::{self, DiskConfig};
use allocatbelt_app_ports::memory::{self, MemoryConfig};

fn resources(memory_bytes: usize, disk_ops: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: memory_bytes,
    disk_concurrent_ops: disk_ops,
    network_concurrent_ops: 0,
  })
}

#[test]
fn memory_kernel_keeps_both_outputs_charged_in_a_shared_scope() {
  let ledger = resources(1024, 0);
  let sentinel = ledger.try_alloc_zeroed(1).expect("sentinel should fit");
  let config = MemoryConfig {
    initial_bytes: 64,
    grown_bytes: 128,
    seed: 91,
  };
  let first = memory::run_operation(&ledger, config).expect("first output should be built");
  let second = memory::run_operation(&ledger, config).expect("second output should be built");
  assert!(!first.report.peak_replacement_was_enforced);
  assert_eq!(ledger.snapshot().managed_memory, 257);
  assert_eq!(first.report.checksum, second.report.checksum);
  assert_eq!(first.report.charged_after_growth, 128);
  drop(first);
  assert_eq!(ledger.snapshot().managed_memory, 129);
  drop(second);
  drop(sentinel);
  assert_eq!(ledger.snapshot().managed_memory, 0);
}

#[test]
fn original_memory_run_still_requires_an_idle_scope_and_checks_replacement() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 4,
    max_scopes: 2,
  })
  .expect("async runtime should start");
  let ledger = resources(1024, 0);
  let sentinel = ledger.try_alloc_zeroed(1).expect("sentinel should fit");
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("scope should open");
  let result = runtime
    .block_on(memory::run(
      &scope,
      ledger.clone(),
      MemoryConfig {
        initial_bytes: 64,
        grown_bytes: 128,
        seed: 13,
      },
    ))
    .expect("root poll should complete");
  assert!(
    result.is_err(),
    "functional run must reject a non-idle ledger"
  );
  drop(sentinel);
  runtime.block_on(scope.close()).expect("scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  assert_eq!(ledger.snapshot().managed_memory, 0);
}

#[test]
fn disk_kernel_runs_concurrently_without_per_operation_global_zero_checks() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 4,
    max_outstanding: 8,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 4,
    max_outstanding: 8,
    max_scopes: 2,
  })
  .expect("async runtime should start");
  let ledger = resources(2 * 8192, 8);
  let sentinel = ledger.try_alloc_zeroed(1).expect("sentinel should fit");
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("scope should open");
  let fs = FsHandle::new(blocking.handle(), ledger.clone());
  let first_fs = fs.clone();
  let second_fs = fs.clone();
  let first_resources = ledger.clone();
  let second_resources = ledger.clone();
  let first = scope
    .spawn(async move {
      disk::run_operation(
        &first_fs,
        &first_resources,
        DiskConfig {
          bytes: 4096,
          offset: 11,
          seed: 5,
        },
      )
      .await
    })
    .expect("first disk operation should admit");
  let second = scope
    .spawn(async move {
      disk::run_operation(
        &second_fs,
        &second_resources,
        DiskConfig {
          bytes: 4096,
          offset: 17,
          seed: 6,
        },
      )
      .await
    })
    .expect("second disk operation should admit");
  let first = runtime
    .block_on(first)
    .expect("first result should publish")
    .expect("first task should finish")
    .expect("first disk operation should complete");
  let second = runtime
    .block_on(second)
    .expect("second result should publish")
    .expect("second task should finish")
    .expect("second disk operation should complete");
  assert_eq!(first.bytes, 4096);
  assert_eq!(second.bytes, 4096);
  assert_eq!(
    first.checksum,
    disk::expected_checksum(DiskConfig {
      bytes: 4096,
      offset: 11,
      seed: 5,
    })
    .expect("first reference checksum should validate")
  );
  assert_eq!(
    second.checksum,
    disk::expected_checksum(DiskConfig {
      bytes: 4096,
      offset: 17,
      seed: 6,
    })
    .expect("second reference checksum should validate")
  );
  assert_ne!(first.checksum, second.checksum);
  assert!(first.temp_directory_removed && second.temp_directory_removed);
  assert!(first.resources_after_cleanup.managed_memory >= 1);
  assert!(second.resources_after_cleanup.managed_memory >= 1);
  let idle_only = runtime
    .block_on(disk::run(
      &scope,
      fs.clone(),
      ledger.clone(),
      DiskConfig {
        bytes: 4096,
        offset: 23,
        seed: 7,
      },
    ))
    .expect("disk wrapper root should complete");
  assert!(
    idle_only.is_err(),
    "functional run must reject a non-idle ledger"
  );
  drop(sentinel);
  runtime.block_on(scope.close()).expect("scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  assert_eq!(ledger.snapshot().managed_memory, 0);
  assert_eq!(ledger.snapshot().disk_ops, 0);
}
