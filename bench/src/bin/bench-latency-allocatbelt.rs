//! Latency probe with allocatbelt installed as the global allocator.
#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::process::ExitCode {
  allocatbelt_bench::latency::main("allocatbelt")
}
