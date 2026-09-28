//! Workloads on allocatbelt.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() {
  // The recommended setup: freed memory is returned from a background
  // thread, also while the process is idle.
  GLOBAL.start_purge_thread().expect("spawn the purge thread");
  allocatbelt_bench::run("allocatbelt");
}
