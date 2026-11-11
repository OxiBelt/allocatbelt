//! Retained per-thread allocator-cache probe. It reports memory samples only;
//! it is not a latency or throughput benchmark.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::process::ExitCode {
  match allocatbelt_bench::cache_retention::run_cli() {
    Ok(()) => std::process::ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("bench-cache-retained-allocatbelt: {error}");
      std::process::ExitCode::FAILURE
    }
  }
}
