//! Executor benchmark on secure mimalloc, OxiBelt's current x86_64 allocator.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
  allocatbelt_bench::runtime::main("mimalloc-secure")
}
