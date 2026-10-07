use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::fs::FsHandle;
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::{Config, Resources, Runtime, ShutdownMode};
use allocatbelt_app_ports::PortResult;
use allocatbelt_app_ports::disk::{self, DiskConfig, MAX_DISK_BYTES, MAX_DISK_OFFSET};

fn main() -> PortResult<()> {
  let mut config = DiskConfig::default();
  for (index, argument) in std::env::args().skip(1).enumerate() {
    match index {
      0 => config.bytes = argument.parse()?,
      1 => config.offset = argument.parse()?,
      _ => {
        return Err(std::io::Error::other("usage: disk [bytes<=1048576] [offset<=1048576]").into());
      }
    }
  }
  if config.bytes == 0 || config.bytes > MAX_DISK_BYTES || config.offset > MAX_DISK_OFFSET {
    return Err(std::io::Error::other("disk arguments exceed their functional bounds").into());
  }

  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  })?;
  let async_runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 4,
    max_scopes: 2,
  })?;
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 2 * MAX_DISK_BYTES,
    disk_concurrent_ops: 1,
    network_concurrent_ops: 0,
  });
  let fs = FsHandle::new(blocking.handle(), resources.clone());
  let scope = async_runtime.scope_with_resources(&resources)?;
  let transaction = async_runtime.block_on(disk::run(&scope, fs, resources.clone(), config));

  let close = async_runtime.block_on(scope.close());
  let async_shutdown = async_runtime.shutdown(AsyncShutdown::Drain);
  let blocking_shutdown = blocking.shutdown(ShutdownMode::Drain);
  let report = transaction??;
  close?;
  async_shutdown?;
  blocking_shutdown?;
  if !report.temp_directory_removed {
    return Err(std::io::Error::other("disk temporary directory was not removed").into());
  }
  let snapshot = resources.snapshot();
  if snapshot.managed_memory != 0 || snapshot.disk_ops != 0 || snapshot.network_ops != 0 {
    return Err(std::io::Error::other("disk workload retained a managed charge").into());
  }
  println!(
    "disk_checksum={:016x} bytes={} offset={} temp_removed={}",
    report.checksum, report.bytes, report.offset, report.temp_directory_removed
  );
  Ok(())
}
