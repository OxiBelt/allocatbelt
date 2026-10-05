//! Executor benchmark on allocatbelt.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::process::ExitCode {
  // The recommended setup, as in `bench-allocatbelt`: housekeeping on a
  // background thread.
  GLOBAL
    .start_maintenance_thread()
    .expect("spawn the maintenance thread");
  allocatbelt_bench::runtime::main("allocatbelt")
}
