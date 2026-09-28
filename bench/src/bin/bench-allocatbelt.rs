//! Workloads on allocatbelt.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() {
  // The recommended setup: housekeeping runs on a background thread, which
  // also returns freed memory while the process is idle.
  GLOBAL
    .start_maintenance_thread()
    .expect("spawn the maintenance thread");
  allocatbelt_bench::run("allocatbelt");
  // Who ran the passes: the maintenance thread, or allocating threads
  // (past the hard limit, or while it was not yet running).
  let s = GLOBAL.maintenance_stats();
  println!(
    "allocatbelt\thousekeeping\tthread: {} budget, {} decay, {} force; inline: {} budget, {} decay; {} wakeups",
    s.budget_passes,
    s.decay_passes,
    s.force_passes,
    s.inline_budget_passes,
    s.inline_decay_passes,
    s.wakeups
  );
}
