use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};
use allocatbelt::runtime::{Config, Resources, Runtime, ShutdownMode};
use allocatbelt_app_ports::PortResult;
use allocatbelt_app_ports::http::{self, HttpConfig, MAX_BODY_BYTES, MAX_REQUEST_BYTES};

fn main() -> PortResult<()> {
  let mut config = HttpConfig::default();
  if let Some(argument) = std::env::args().nth(1) {
    config.body_bytes = argument.parse()?;
  }
  if std::env::args().nth(2).is_some() || config.body_bytes > MAX_BODY_BYTES {
    return Err(std::io::Error::other("usage: tcp_http [body-bytes<=8192]").into());
  }

  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  })?;
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 3,
    max_waiters: 6,
  })?;
  let async_runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 4,
    max_scopes: 2,
  })?;
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 3 * MAX_REQUEST_BYTES + 2 * 128,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 2,
  });
  let scope = async_runtime.scope_with_resources(&resources)?;
  let transaction = async_runtime.block_on(http::loopback_transaction(
    &scope,
    blocking.handle(),
    reactor.handle(),
    resources.clone(),
    config,
  ));

  let close = async_runtime.block_on(scope.close());
  let async_shutdown = async_runtime.shutdown(AsyncShutdown::Drain);
  let blocking_shutdown = blocking.shutdown(ShutdownMode::Drain);
  let reactor_shutdown = reactor.shutdown();
  let checksum = transaction??;
  close?;
  async_shutdown?;
  blocking_shutdown?;
  reactor_shutdown?;
  let snapshot = resources.snapshot();
  if snapshot.managed_memory != 0 || snapshot.disk_ops != 0 || snapshot.network_ops != 0 {
    return Err(std::io::Error::other("HTTP workload retained a managed charge").into());
  }
  println!(
    "http_checksum={checksum:016x} body_bytes={}",
    config.body_bytes
  );
  Ok(())
}
