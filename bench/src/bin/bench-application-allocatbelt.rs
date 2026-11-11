//! Application comparison lane using allocatbelt as the global allocator.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::process::ExitCode {
  GLOBAL
    .start_maintenance_thread()
    .expect("spawn the maintenance thread");
  allocatbelt_bench::application::main("allocatbelt")
}
