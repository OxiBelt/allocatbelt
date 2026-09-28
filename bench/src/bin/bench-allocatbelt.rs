//! Workloads on allocatbelt.

#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() {
  // `ALLOCATBELT_BENCH_IO_URING=0` or `=1` picks the maintenance thread's
  // purge backend (default: the allocator's).
  match std::env::var("ALLOCATBELT_BENCH_IO_URING").as_deref() {
    Ok("0") => GLOBAL.set_io_uring(false),
    Ok("1") => GLOBAL.set_io_uring(true),
    _ => {}
  }
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
    "allocatbelt\thousekeeping\tthread: {} budget, {} decay, {} force; inline: {} budget, {} decay; {} wakeups; {} runs in {} batches ({:?})",
    s.budget_passes,
    s.decay_passes,
    s.force_passes,
    s.inline_budget_passes,
    s.inline_decay_passes,
    s.wakeups,
    s.purged_runs,
    s.purge_batches,
    GLOBAL.purge_backend(),
  );
}
