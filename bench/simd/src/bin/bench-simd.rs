//! Runs every detected variant of every candidate kernel at the sizes the
//! allocator uses and prints one table (or CSV) row per measurement.
//!
//! ```text
//! bench-simd [--quick] [--csv] [--family nonzero|popcount|age|zero|copy]
//! ```

use std::hint::black_box;

use allocatbelt_simd_bench::harness::{Config, Measurement, measure};
use allocatbelt_simd_bench::kernels::{Families, Tier, Variant};
use allocatbelt_simd_bench::perf::{Counters, EVENTS};

/// `find_nonzero_local_words` / `reduce_local_masks` lengths: one segment's
/// words, a few segments, the 64 page records of a segment, and the 256
/// `seg_used` words of the whole arena.
const WORD_LENGTHS: [usize; 5] = [1, 4, 16, 64, 256];
/// Candidate pages per segment for the age classification.
const AGE_CANDIDATES: [u32; 4] = [1, 8, 32, 64];
/// Block sizes: small classes, the 8 KiB small limit, a page (64 KiB), a
/// large block and a segment (4 MiB).
const BYTE_SIZES: [usize; 8] = [16, 64, 256, 1024, 8192, 65_536, 1 << 20, 4 << 20];

struct Report {
  csv: bool,
}

impl Report {
  fn header(&self, counters: bool) {
    if self.csv {
      let names: Vec<&str> = EVENTS.iter().map(|(n, _)| *n).collect();
      println!(
        "family,size,variant,tier,iters,median_ns,p95_ns,p99_ns,vs_baseline,throughput,unit,{}",
        names.join(",")
      );
    } else {
      let extra = if counters {
        " cycles/op | instr/op | branches/op | br-miss/op | cache-miss/op |"
      } else {
        ""
      };
      println!(
        "| family | size | variant | tier | median ns | p95 ns | p99 ns | vs baseline | throughput |{extra}"
      );
      let cols = if counters { 14 } else { 9 };
      println!("|{}", "---|".repeat(cols));
    }
  }

  #[allow(clippy::too_many_arguments, reason = "one table row")]
  fn row(
    &self,
    family: &str,
    size: &str,
    name: &str,
    tier: Tier,
    m: &Measurement,
    baseline: f64,
    per_op: f64,
    unit: &str,
  ) {
    let ratio = baseline / m.median_ns;
    let throughput = per_op / m.median_ns;
    if self.csv {
      let counts: Vec<String> = match m.counters {
        Some(c) => c.iter().map(|v| format!("{v:.2}")).collect(),
        None => vec![String::new(); EVENTS.len()],
      };
      println!(
        "{family},{size},{name},{},{},{:.3},{:.3},{:.3},{ratio:.3},{throughput:.4},{unit},{}",
        tier.label(),
        m.iters,
        m.median_ns,
        m.p95_ns,
        m.p99_ns,
        counts.join(",")
      );
    } else {
      let counts = m.counters.map_or(String::new(), |c| {
        c.iter().map(|v| format!(" {v:.1} |")).collect()
      });
      println!(
        "| {family} | {size} | {name} | {} | {:.2} | {:.2} | {:.2} | {ratio:.2}x | {throughput:.2} {unit} |{counts}",
        tier.label(),
        m.median_ns,
        m.p95_ns,
        m.p99_ns,
      );
    }
  }
}

fn main() {
  let args: Vec<String> = std::env::args().skip(1).collect();
  let cfg = if args.iter().any(|a| a == "--quick") {
    Config::QUICK
  } else {
    Config::FULL
  };
  let report = Report {
    csv: args.iter().any(|a| a == "--csv"),
  };
  let only = args
    .iter()
    .position(|a| a == "--family")
    .and_then(|i| args.get(i + 1))
    .cloned();
  let wants = |name: &str| only.as_deref().is_none_or(|o| o == name);

  let mut counters = Counters::open();
  environment(&cfg, &counters, report.csv);
  report.header(counters.is_ok());
  let mut c = counters.as_mut().ok();

  let f = Families::detected();
  let mut rng = 0x9e37_79b9_7f4a_7c15u64;
  let mut next = move || {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    rng
  };

  if wants("nonzero") {
    for n in WORD_LENGTHS {
      let words: Vec<u64> = (0..n)
        .map(|_| {
          let w = next();
          if w % 4 == 0 { 0 } else { w }
        })
        .collect();
      let mut out = vec![0u64; n.div_ceil(64)];
      family(
        &report,
        cfg,
        &mut c,
        "nonzero",
        &n.to_string(),
        &f.nonzero,
        n as f64,
        "Gword/s",
        |k| {
          k(black_box(&words), black_box(&mut out));
        },
      );
    }
  }
  if wants("popcount") {
    for n in WORD_LENGTHS {
      let words: Vec<u64> = (0..n).map(|_| next()).collect();
      family(
        &report,
        cfg,
        &mut c,
        "popcount",
        &n.to_string(),
        &f.popcount,
        n as f64,
        "Gword/s",
        |k| {
          black_box(k(black_box(&words)));
        },
      );
    }
  }
  if wants("age") {
    for bits in AGE_CANDIDATES {
      let mut since = [0u64; 64];
      for s in &mut since {
        *s = next() % 32;
      }
      let candidates = spread(bits, &mut next);
      family(
        &report,
        cfg,
        &mut c,
        "age",
        &format!("{bits}/64"),
        &f.age,
        64.0,
        "Gpage/s",
        |k| {
          black_box(k(black_box(&since), black_box(candidates), black_box(16)));
        },
      );
    }
  }
  if wants("zero") {
    for n in BYTE_SIZES {
      let mut buf = vec![1u8; n];
      family(
        &report,
        cfg,
        &mut c,
        "zero",
        &bytes(n),
        &f.zero,
        n as f64,
        "GB/s",
        |k| {
          k(black_box(&mut buf));
        },
      );
    }
  }
  if wants("copy") {
    for n in BYTE_SIZES {
      let src = vec![7u8; n];
      let mut dst = vec![0u8; n];
      family(
        &report,
        cfg,
        &mut c,
        "copy",
        &bytes(n),
        &f.copy,
        n as f64,
        "GB/s",
        |k| {
          k(black_box(&mut dst), black_box(&src));
        },
      );
    }
  }
}

/// Measures every variant of one family at one size; the first variant is
/// the baseline the ratios refer to.
#[allow(clippy::too_many_arguments, reason = "one family at one size")]
fn family<F: Copy>(
  report: &Report,
  cfg: Config,
  counters: &mut Option<&mut Counters>,
  name: &str,
  size: &str,
  variants: &[Variant<F>],
  per_op: f64,
  unit: &str,
  mut call: impl FnMut(F),
) {
  let mut baseline = f64::NAN;
  for v in variants {
    let k = v.get();
    let m = measure(cfg, counters.as_deref_mut(), || call(k));
    if baseline.is_nan() {
      baseline = m.median_ns;
    }
    report.row(name, size, v.name(), v.tier(), &m, baseline, per_op, unit);
  }
}

/// `bits` distinct random bits of a word.
fn spread(bits: u32, next: &mut impl FnMut() -> u64) -> u64 {
  let mut m = 0u64;
  while m.count_ones() < bits {
    m |= 1 << (next() % 64);
  }
  m
}

fn bytes(n: usize) -> String {
  match n {
    n if n >= 1 << 20 => format!("{} MiB", n >> 20),
    n if n >= 1 << 10 => format!("{} KiB", n >> 10),
    n => format!("{n} B"),
  }
}

/// Prints what a result needs to be comparable (plan §22: machine, CPU,
/// kernel, compiler, flags, runs).
fn environment(cfg: &Config, counters: &std::io::Result<Counters>, csv: bool) {
  let cpu = cpu_model();
  let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
  let mut flags = Vec::new();
  for (on, name) in [
    (cfg!(target_feature = "avx2"), "avx2"),
    (cfg!(target_feature = "avx512f"), "avx512f"),
    (cfg!(target_feature = "neon"), "neon"),
    (cfg!(target_feature = "sve"), "sve"),
    (cfg!(target_feature = "zbb"), "zbb"),
    (cfg!(allocatbelt_rvv), "v"),
  ] {
    if on {
      flags.push(name);
    }
  }
  let counters = match counters {
    Ok(_) => "available (user space, this thread)".to_string(),
    Err(e) => format!("unavailable ({e})"),
  };
  let lines = [
    format!("arch: {}", std::env::consts::ARCH),
    format!("cpu: {cpu}"),
    format!("kernel: {}", kernel.trim()),
    format!("rustc: {}", env!("ALLOCATBELT_RUSTC_VERSION")),
    format!("build target features: {}", flags.join(",")),
    format!("detected: {:?}", allocatbelt_arch::detected_features()),
    format!("repetitions: {} x ~{} us", cfg.reps, cfg.rep_ns / 1000),
    format!("counters: {counters}"),
  ];
  for l in lines {
    if csv {
      println!("# {l}");
    } else {
      println!("- {l}");
    }
  }
  if !csv {
    println!();
  }
}

fn cpu_model() -> String {
  let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
  let field = |key: &str| {
    info
      .lines()
      .find(|l| l.starts_with(key))
      .and_then(|l| l.split(':').nth(1))
      .map(|v| v.trim().to_string())
  };
  field("model name")
    .or_else(|| {
      let part = field("CPU part")?;
      Some(format!(
        "implementer {} part {part}",
        field("CPU implementer")?
      ))
    })
    .or_else(|| field("uarch"))
    .unwrap_or_else(|| "unknown".into())
}
