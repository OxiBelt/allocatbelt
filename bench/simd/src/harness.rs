//! Timing: calibrated repetitions, percentiles, and optional counters.

use std::hint::black_box;
use std::time::Instant;

use crate::perf::{Counters, EVENTS};

/// How long and how often to measure.
#[derive(Debug, Clone, Copy)]
pub struct Config {
  /// Timed repetitions per variant and size; the percentiles are over these.
  pub reps: usize,
  /// Target duration of one repetition, in nanoseconds.
  pub rep_ns: u64,
}

impl Config {
  /// Enough repetitions for a stable p99 on an idle machine.
  pub const FULL: Self = Self {
    reps: 201,
    rep_ns: 200_000,
  };
  /// A smoke run (CI, qemu): the numbers are not meaningful.
  pub const QUICK: Self = Self {
    reps: 11,
    rep_ns: 20_000,
  };
}

/// Result of measuring one operation.
#[derive(Debug, Clone, Copy)]
pub struct Measurement {
  /// Median time per operation.
  pub median_ns: f64,
  /// 95th percentile of the per-repetition time per operation.
  pub p95_ns: f64,
  /// 99th percentile of the per-repetition time per operation.
  pub p99_ns: f64,
  /// Operations per repetition after calibration.
  pub iters: u64,
  /// Counts per operation, in the order of [`EVENTS`], when available.
  pub counters: Option<[f64; EVENTS.len()]>,
}

/// Measures `op`, which must do one operation per call.
pub fn measure(cfg: Config, counters: Option<&mut Counters>, mut op: impl FnMut()) -> Measurement {
  let iters = calibrate(cfg.rep_ns, &mut op);
  // Warm caches, branch predictors and the frequency governor.
  run(iters, &mut op);
  let mut per_op: Vec<f64> = Vec::with_capacity(cfg.reps);
  if let Some(c) = counters.as_deref() {
    c.start();
  }
  for _ in 0..cfg.reps {
    per_op.push(run(iters, &mut op) / iters as f64);
  }
  let total = (cfg.reps as u64 * iters) as f64;
  let counts = counters
    .and_then(|c| c.stop().ok())
    .map(|v| v.map(|x| x as f64 / total));
  per_op.sort_by(f64::total_cmp);
  Measurement {
    median_ns: percentile(&per_op, 0.50),
    p95_ns: percentile(&per_op, 0.95),
    p99_ns: percentile(&per_op, 0.99),
    iters,
    counters: counts,
  }
}

/// Nanoseconds for `iters` calls.
fn run(iters: u64, op: &mut impl FnMut()) -> f64 {
  let t = Instant::now();
  for _ in 0..iters {
    op();
  }
  black_box(t.elapsed().as_nanos() as f64)
}

/// Doubles the iteration count until a repetition takes a quarter of the
/// target, then scales to the target.
fn calibrate(rep_ns: u64, op: &mut impl FnMut()) -> u64 {
  let mut iters = 1u64;
  loop {
    let ns = run(iters, op);
    if ns >= rep_ns as f64 / 4.0 || iters >= 1 << 30 {
      return ((iters as f64 * rep_ns as f64 / ns.max(1.0)) as u64).max(1);
    }
    iters *= 2;
  }
}

/// Nearest-rank percentile of sorted `v`.
fn percentile(v: &[f64], p: f64) -> f64 {
  if v.is_empty() {
    return f64::NAN;
  }
  let rank = ((p * v.len() as f64).ceil() as usize).clamp(1, v.len());
  v[rank - 1]
}

#[cfg(test)]
mod tests {
  use super::{Config, measure, percentile};

  #[test]
  fn percentiles_are_nearest_rank() {
    let v: Vec<f64> = (1..=100).map(f64::from).collect();
    assert_eq!(percentile(&v, 0.5), 50.0);
    assert_eq!(percentile(&v, 0.95), 95.0);
    assert_eq!(percentile(&v, 0.99), 99.0);
    assert_eq!(percentile(&[7.0], 0.99), 7.0);
  }

  #[test]
  fn measures_something() {
    let mut x = 0u64;
    let m = measure(Config::QUICK, None, || x = std::hint::black_box(x + 1));
    assert!(m.median_ns > 0.0 && m.median_ns <= m.p95_ns && m.p95_ns <= m.p99_ns);
    assert!(m.iters >= 1);
  }
}
