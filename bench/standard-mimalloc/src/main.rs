//! Standard mimalloc comparator in an isolated Cargo feature graph.
#[path = "../../src/latency.rs"]
mod latency;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
  latency::main("mimalloc-standard")
}
