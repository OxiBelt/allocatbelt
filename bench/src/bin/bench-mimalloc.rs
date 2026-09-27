//! Workloads on secure mimalloc, OxiBelt's current x86_64 allocator.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    allocatbelt_bench::run("mimalloc-secure");
}
