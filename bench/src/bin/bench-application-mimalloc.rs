//! Application comparison lane using secure mimalloc.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
  allocatbelt_bench::application::main("mimalloc-secure")
}
