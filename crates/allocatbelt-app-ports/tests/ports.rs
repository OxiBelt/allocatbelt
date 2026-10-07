use std::future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::fs::FsHandle;
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};
use allocatbelt::runtime::{
  Config as BlockingConfig, Resources, Runtime as BlockingRuntime, ShutdownMode,
};
use allocatbelt_app_ports::cpu::{self, CpuConfig};
use allocatbelt_app_ports::disk::{self, DiskConfig, MAX_DISK_BYTES};
use allocatbelt_app_ports::http::{self, HttpConfig, MAX_REQUEST_BYTES};
use allocatbelt_app_ports::memory::{self, MAX_BUFFER_BYTES, MemoryConfig};

fn async_runtime(max_outstanding: usize) -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding,
    max_scopes: 2,
  })
  .expect("test runtime should start")
}

fn resources(memory: usize, disk: usize, network: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: memory,
    disk_concurrent_ops: disk,
    network_concurrent_ops: network,
  })
}

#[test]
fn cpu_and_managed_growth_complete_under_owned_scopes() {
  let runtime = async_runtime(16);
  let ledger = resources(2 * MAX_BUFFER_BYTES, 0, 0);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("scope should open");
  let cpu_result = runtime
    .block_on(cpu::run(
      &scope,
      CpuConfig {
        jobs: 3,
        rounds: 2000,
        seed: 17,
      },
    ))
    .expect("root should complete")
    .expect("CPU jobs should complete");
  let memory_report = runtime
    .block_on(memory::run(&scope, ledger.clone(), MemoryConfig::default()))
    .expect("root should complete")
    .expect("managed growth should complete");
  assert_ne!(cpu_result, 0);
  assert!(memory_report.report.peak_replacement_was_enforced);
  assert!(memory_report.report.charged_after_growth >= MemoryConfig::default().grown_bytes);
  assert_eq!(
    ledger.snapshot().managed_memory,
    memory_report.report.charged_after_growth
  );
  drop(memory_report);
  runtime
    .block_on(scope.close())
    .expect("scope cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("worker shutdown should finish");
  assert_eq!(ledger.snapshot().managed_memory, 0);
}

#[test]
fn owned_scope_cancellation_drops_managed_captures_before_close_returns() {
  struct DropCount(Arc<AtomicUsize>);
  impl Drop for DropCount {
    fn drop(&mut self) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  let runtime = async_runtime(2);
  let ledger = resources(64, 0, 0);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("scope should open");
  let started = Arc::new(AtomicBool::new(false));
  let drops = Arc::new(AtomicUsize::new(0));
  let (started_tx, started_rx) = mpsc::channel();
  let task_resources = ledger.clone();
  let task_started = Arc::clone(&started);
  let task_drops = Arc::clone(&drops);
  let detached = scope
    .spawn(async move {
      let buffer = task_resources
        .try_alloc_zeroed(64)
        .expect("charge should fit");
      let guard = DropCount(task_drops);
      task_started.store(true, Ordering::Release);
      started_tx.send(()).expect("test receiver is live");
      future::pending::<()>().await;
      drop(buffer);
      drop(guard);
    })
    .expect("task should be admitted");
  drop(detached);
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("task should enter its pending poll");
  assert!(started.load(Ordering::Acquire));
  assert_eq!(ledger.snapshot().managed_memory, 64);
  runtime
    .block_on(scope.close())
    .expect("scope cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("worker shutdown should finish");
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  assert_eq!(ledger.snapshot().managed_memory, 0);
}

#[test]
fn loopback_http_uses_reactor_tcp_and_releases_all_charges() {
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
  let runtime = async_runtime(4);
  let ledger = resources(3 * MAX_REQUEST_BYTES + 256, 0, 2);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("scope should open");
  let digest = runtime
    .block_on(http::loopback_transaction(
      &scope,
      blocking.handle(),
      reactor.handle(),
      ledger.clone(),
      HttpConfig {
        body_bytes: 1739,
        seed: 91,
      },
    ))
    .expect("root should complete")
    .expect("loopback request should succeed");
  let expected_http_checksum = memory::checksum(
    &(0..1739)
      .map(|index| memory::pattern_byte(91, index))
      .collect::<Vec<_>>(),
  );
  assert_eq!(digest, expected_http_checksum);
  runtime
    .block_on(scope.close())
    .expect("scope cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async shutdown should finish");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking shutdown should finish");
  reactor.shutdown().expect("reactor shutdown should finish");
  let snapshot = ledger.snapshot();
  assert_eq!(snapshot.managed_memory, 0);
  assert_eq!(snapshot.network_ops, 0);
}

#[test]
fn disk_transaction_uses_owned_offsets_syncs_reads_back_and_removes_temp_tree() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let runtime = async_runtime(4);
  let ledger = resources(2 * MAX_DISK_BYTES, 1, 0);
  let scope = runtime
    .scope_with_resources(&ledger)
    .expect("scope should open");
  let fs = FsHandle::new(blocking.handle(), ledger.clone());
  let report = runtime
    .block_on(disk::run(
      &scope,
      fs,
      ledger.clone(),
      DiskConfig {
        bytes: 192 * 1024 + 17,
        offset: 1027,
        seed: 33,
      },
    ))
    .expect("root should complete")
    .expect("disk transaction should succeed");
  assert_eq!(report.bytes, 192 * 1024 + 17);
  assert_eq!(report.offset, 1027);
  assert!(report.temp_directory_removed);
  runtime
    .block_on(scope.close())
    .expect("scope cleanup should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async shutdown should finish");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("filesystem workers should finish");
  let snapshot = ledger.snapshot();
  assert_eq!(snapshot.managed_memory, 0);
  assert_eq!(snapshot.disk_ops, 0);
}
