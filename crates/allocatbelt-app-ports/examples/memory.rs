use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt_app_ports::PortResult;
use allocatbelt_app_ports::memory::{self, MAX_BUFFER_BYTES, MemoryConfig};

fn main() -> PortResult<()> {
  let mut config = MemoryConfig::default();
  for (index, argument) in std::env::args().skip(1).enumerate() {
    match index {
      0 => config.initial_bytes = argument.parse()?,
      1 => config.grown_bytes = argument.parse()?,
      _ => {
        return Err(std::io::Error::other("usage: memory [initial-bytes] [grown-bytes]").into());
      }
    }
  }
  if config.initial_bytes == 0
    || config.grown_bytes <= config.initial_bytes
    || config.grown_bytes > MAX_BUFFER_BYTES
  {
    return Err(std::io::Error::other("memory arguments exceed their functional bounds").into());
  }
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 4,
    max_scopes: 2,
  })?;
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 2 * MAX_BUFFER_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let scope = runtime.scope_with_resources(&resources)?;
  let work = runtime.block_on(memory::run(&scope, resources.clone(), config));
  let close = runtime.block_on(scope.close());
  let shutdown = runtime.shutdown(AsyncShutdown::Drain);
  let report = work??;
  close?;
  shutdown?;
  if resources.snapshot().managed_memory != 0 {
    return Err(
      std::io::Error::other("memory workload retained managed bytes after shutdown").into(),
    );
  }
  println!(
    "memory_checksum={:016x} charged_after_growth={} peak_replacement_enforced={}",
    report.checksum, report.charged_after_growth, report.peak_replacement_was_enforced
  );
  Ok(())
}
