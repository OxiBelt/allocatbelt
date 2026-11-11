//! Executor benchmark on the system allocator (glibc malloc).

fn main() -> std::process::ExitCode {
  allocatbelt_bench::runtime::main("system")
}
