use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt_app_ports::PortResult;
use allocatbelt_app_ports::cpu::{self, CpuConfig, MAX_JOBS, MAX_ROUNDS};

fn main() -> PortResult<()> {
  let mut config = CpuConfig::default();
  for (index, argument) in std::env::args().skip(1).enumerate() {
    match index {
      0 => config.jobs = argument.parse()?,
      1 => config.rounds = argument.parse()?,
      _ => {
        return Err(std::io::Error::other("usage: cpu [jobs<=16] [rounds<=1000000]").into());
      }
    }
  }
  if config.jobs == 0 || config.jobs > MAX_JOBS || config.rounds == 0 || config.rounds > MAX_ROUNDS
  {
    return Err(std::io::Error::other("CPU arguments exceed their functional bounds").into());
  }
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: MAX_JOBS,
    max_scopes: 2,
  })?;
  let resources = ResourceScope::new(ResourceLimits::default());
  let scope = runtime.scope_with_resources(&resources)?;
  let work = runtime.block_on(cpu::run(&scope, config));
  let close = runtime.block_on(scope.close());
  let shutdown = runtime.shutdown(AsyncShutdown::Drain);
  let digest = work??;
  close?;
  shutdown?;
  let snapshot = resources.snapshot();
  if snapshot.managed_memory != 0 || snapshot.disk_ops != 0 || snapshot.network_ops != 0 {
    return Err(std::io::Error::other("CPU workload leaked a managed resource charge").into());
  }
  println!("cpu_digest={digest:016x} jobs={}", config.jobs);
  Ok(())
}
