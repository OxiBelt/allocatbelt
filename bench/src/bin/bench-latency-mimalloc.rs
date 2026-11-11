//! Latency probe with secure mimalloc installed as the global allocator.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
  allocatbelt_bench::latency::main("mimalloc-secure")
}
