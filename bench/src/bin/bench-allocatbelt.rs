//! Workloads on allocatbelt.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() {
    allocatbelt_bench::run("allocatbelt");
}
