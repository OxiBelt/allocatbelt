//! Continuous mixed application soak through allocatbelt's owning runtime.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::process::ExitCode {
  match GLOBAL.start_maintenance_thread() {
    Ok(_) => allocatbelt_bench::soak::run_cli(),
    Err(error) => {
      eprintln!("allocator maintenance startup failed: {error}");
      std::process::ExitCode::FAILURE
    }
  }
}
