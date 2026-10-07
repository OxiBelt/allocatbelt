//! Latency probe with the system allocator installed.
fn main() -> std::process::ExitCode {
  allocatbelt_bench::latency::main("system")
}
