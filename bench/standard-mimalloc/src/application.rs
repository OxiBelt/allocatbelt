//! Standard-mimalloc application comparator in its isolated Cargo graph.
#[path = "../../src/application.rs"]
mod application;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
  application::main("mimalloc-standard")
}
