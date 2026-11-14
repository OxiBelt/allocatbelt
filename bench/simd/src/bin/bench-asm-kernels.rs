//! Measures allocatbelt's experimental assembly kernels (feature
//! `experimental-asm-kernels`) against the portable loops they replace,
//! on the inputs the thread cache gives them.
//!
//! ```text
//! bench-asm-kernels [--quick] [--csv]
//! ```
//!
//! The kernel source is the allocator's own file for this build's ISA
//! level, included by path, so the numbers are for the code the allocator
//! would run. Both variants are inlined into the timed loop, as they are
//! into the allocator's paths.

use std::cell::Cell;
use std::hint::black_box;

use std::sync::atomic::{AtomicU64, Ordering};

use allocatbelt_core_check::core::bits::pick_bit;
use allocatbelt_core_check::core::{list_holds, nonzero_words, pack_blocks, unpack_blocks};
use allocatbelt_simd_bench::harness::{Config, Measurement, measure};
use allocatbelt_simd_bench::perf::{Counters, EVENTS};

#[cfg(all(
  target_arch = "x86_64",
  target_feature = "avx512f",
  target_feature = "avx512bw",
  target_feature = "avx512cd",
  target_feature = "avx512dq",
  target_feature = "avx512vl"
))]
#[path = "../../../../crates/allocatbelt/src/arch/asm_kernels/x86_64_v4.rs"]
#[allow(unsafe_code, reason = "the allocator's assembly kernels")]
mod asm;

#[cfg(all(
  target_arch = "x86_64",
  not(all(
    target_feature = "avx512f",
    target_feature = "avx512bw",
    target_feature = "avx512cd",
    target_feature = "avx512dq",
    target_feature = "avx512vl"
  ))
))]
#[path = "../../../../crates/allocatbelt/src/arch/asm_kernels/x86_64_v3.rs"]
#[allow(unsafe_code, reason = "the allocator's assembly kernels")]
mod asm;

#[cfg(target_arch = "aarch64")]
#[path = "../../../../crates/allocatbelt/src/arch/asm_kernels/aarch64.rs"]
#[allow(unsafe_code, reason = "the allocator's assembly kernels")]
mod asm;

#[cfg(target_arch = "riscv64")]
#[path = "../../../../crates/allocatbelt/src/arch/asm_kernels/riscv64.rs"]
#[allow(unsafe_code, reason = "the allocator's assembly kernels")]
mod asm;

/// Inputs per case; the timed loop cycles through them so that neither a
/// branch predictor nor a value predictor learns one answer.
const INPUTS: usize = 1024;

struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }
}

/// A list as a refill leaves it and pops then shuffle it: distinct block
/// numbers in a random order.
fn shuffled_list(rng: &mut Rng) -> [Cell<u8>; 64] {
  let mut blocks: [u8; 64] = std::array::from_fn(|k| k as u8);
  for k in (1..64).rev() {
    blocks.swap(k, (rng.next() % (k as u64 + 1)) as usize);
  }
  blocks.map(Cell::new)
}

/// A word with `ones` set bits at random positions.
fn word_with(rng: &mut Rng, ones: u32) -> u64 {
  let mut word = 0u64;
  while word.count_ones() < ones {
    word |= 1 << (rng.next() & 63);
  }
  word
}

fn print_header(csv: bool, counters: bool) {
  if csv {
    let names: Vec<&str> = EVENTS.iter().map(|(n, _)| *n).collect();
    println!(
      "kernel,case,variant,iters,median_ns,p95_ns,p99_ns,vs_portable,{}",
      names.join(",")
    );
    return;
  }
  let extra = if counters {
    " cycles/op | instr/op | branches/op | br-miss/op | cache-miss/op |"
  } else {
    ""
  };
  println!("| kernel | case | variant | median ns | p95 ns | p99 ns | vs portable |{extra}");
  println!("|{}", "---|".repeat(if counters { 12 } else { 7 }));
}

fn print_row(csv: bool, kernel: &str, case: &str, variant: &str, m: &Measurement, portable: f64) {
  let ratio = portable / m.median_ns;
  if csv {
    let counts: Vec<String> = match m.counters {
      Some(c) => c.iter().map(|v| format!("{v:.2}")).collect(),
      None => vec![String::new(); EVENTS.len()],
    };
    println!(
      "{kernel},{case},{variant},{},{:.3},{:.3},{:.3},{ratio:.3},{}",
      m.iters,
      m.median_ns,
      m.p95_ns,
      m.p99_ns,
      counts.join(",")
    );
  } else {
    let counts = m.counters.map_or(String::new(), |c| {
      c.iter().map(|v| format!(" {v:.2} |")).collect()
    });
    println!(
      "| {kernel} | {case} | {variant} | {:.2} | {:.2} | {:.2} | {ratio:.2}x |{counts}",
      m.median_ns, m.p95_ns, m.p99_ns,
    );
  }
}

fn environment(cfg: &Config, counters: &std::io::Result<Counters>, csv: bool) {
  let lead = if csv { "# " } else { "" };
  let cpu = std::fs::read_to_string("/proc/cpuinfo")
    .ok()
    .and_then(|s| {
      s.lines()
        .find(|l| l.starts_with("model name") || l.starts_with("uarch") || l.starts_with("isa"))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.trim().to_owned())
    })
    .unwrap_or_else(|| "unknown".to_owned());
  println!("{lead}arch: {}; cpu: {cpu}", std::env::consts::ARCH);
  println!("{lead}asm implementation: {}", asm::NAME);
  println!(
    "{lead}repetitions: {} of about {} us; inputs per case: {INPUTS}",
    cfg.reps,
    cfg.rep_ns / 1000
  );
  match counters {
    Ok(_) => println!("{lead}hardware counters: available"),
    Err(e) => println!("{lead}hardware counters: unavailable ({e})"),
  }
  println!();
}

fn main() {
  let args: Vec<String> = std::env::args().skip(1).collect();
  let cfg = if args.iter().any(|a| a == "--quick") {
    Config::QUICK
  } else {
    Config::FULL
  };
  let csv = args.iter().any(|a| a == "--csv");
  let mut counters = Counters::open();
  environment(&cfg, &counters, csv);
  print_header(csv, counters.is_ok());
  let mut c = counters.as_mut().ok();
  let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

  // `list_holds`: the free path asks whether the freed block is still in
  // the list of the claimed word. In a correct program it never is (that
  // would be a double free), so the miss is the case that runs; the hit
  // is measured to show the kernel does not depend on the answer.
  for len in [1u8, 8, 32, 64] {
    for hit in [false, true] {
      // A full list of distinct block numbers holds every block.
      if len == 64 && !hit {
        continue;
      }
      let list = shuffled_list(&mut rng);
      let queries: Vec<u8> = (0..INPUTS)
        .map(|_| {
          let k = if hit {
            rng.next() % u64::from(len)
          } else {
            u64::from(len) + rng.next() % u64::from(64 - len)
          };
          list[k as usize].get()
        })
        .collect();
      let case = format!("len {len}, {}", if hit { "hit" } else { "miss" });
      let mut at = 0usize;
      let mut found = 0u64;
      let portable = measure(cfg, c.as_deref_mut(), || {
        let i = queries[at & (INPUTS - 1)];
        at += 1;
        found += u64::from(list_holds(black_box(&list), black_box(len), i));
      });
      black_box(found);
      let mut at = 0usize;
      let mut found_asm = 0u64;
      let kernel = measure(cfg, c.as_deref_mut(), || {
        let i = queries[at & (INPUTS - 1)];
        at += 1;
        found_asm += u64::from(asm::list_holds(black_box(&list), black_box(len), i));
      });
      black_box(found_asm);
      print_row(
        csv,
        "list_holds",
        &case,
        "portable",
        &portable,
        portable.median_ns,
      );
      print_row(csv, "list_holds", &case, "asm", &kernel, portable.median_ns);
    }
  }

  // `unpack_blocks`: a refill unpacks the free blocks of the word it
  // claimed. A fresh page gives full words; a churned page gives sparse
  // ones.
  for ones in [1u32, 4, 16, 32, 48, 64] {
    let words: Vec<u64> = (0..INPUTS).map(|_| word_with(&mut rng, ones)).collect();
    let case = format!("{ones} of 64 free");
    let list: [Cell<u8>; 64] = [const { Cell::new(0) }; 64];
    let mut at = 0usize;
    let mut total = 0u64;
    let portable = measure(cfg, c.as_deref_mut(), || {
      let bits = words[at & (INPUTS - 1)];
      at += 1;
      total += u64::from(unpack_blocks(bits, black_box(&list)));
    });
    black_box(total);
    let mut at = 0usize;
    let mut total_asm = 0u64;
    let kernel = measure(cfg, c.as_deref_mut(), || {
      let bits = words[at & (INPUTS - 1)];
      at += 1;
      total_asm += u64::from(asm::unpack_blocks(bits, black_box(&list)));
    });
    black_box(total_asm);
    print_row(
      csv,
      "unpack_blocks",
      &case,
      "portable",
      &portable,
      portable.median_ns,
    );
    print_row(
      csv,
      "unpack_blocks",
      &case,
      "asm",
      &kernel,
      portable.median_ns,
    );
  }
  // `nonzero_words` + rank pick: a claim, under the shard's lock, picks one
  // of the page's non-zero bitmap words by rank. `two-pass` is the loop the
  // heap ran before the mask (count the non-zero words, then walk to the
  // picked one); `portable` and `asm` build the mask and pick a bit of it.
  // The lengths are the bitmap words of the 16-, 32-, 64-, 128-, 256- and
  // 512-byte classes; about half of the words are zero.
  for n in [64usize, 32, 16, 8, 4, 2] {
    let pages: Vec<Vec<AtomicU64>> = (0..INPUTS)
      .map(|_| {
        (0..n)
          .map(|_| {
            AtomicU64::new(if rng.next() & 1 == 0 {
              0
            } else {
              rng.next() | 1
            })
          })
          .collect()
      })
      .collect();
    let case = format!("{n} words");
    let mut at = 0usize;
    let mut sum = 0u64;
    let two_pass = measure(cfg, c.as_deref_mut(), || {
      let words = &pages[at & (INPUTS - 1)];
      at += 1;
      let r = (at as u32).wrapping_mul(0x9E37_79B9);
      let k = words
        .iter()
        .filter(|w| w.load(Ordering::Relaxed) != 0)
        .count() as u64;
      if k != 0 {
        let rank = (u64::from(r) * k) >> 32;
        let picked = words
          .iter()
          .enumerate()
          .filter(|(_, w)| w.load(Ordering::Relaxed) != 0)
          .nth(rank as usize);
        sum += picked.map_or(0, |(i, _)| i as u64);
      }
    });
    black_box(sum);
    let mut at = 0usize;
    let mut sum_portable = 0u64;
    let portable = measure(cfg, c.as_deref_mut(), || {
      let words = &pages[at & (INPUTS - 1)];
      at += 1;
      let r = (at as u32).wrapping_mul(0x9E37_79B9);
      let mask = nonzero_words(black_box(words));
      if mask != 0 {
        sum_portable += u64::from(pick_bit(mask, r));
      }
    });
    black_box(sum_portable);
    let mut at = 0usize;
    let mut sum_asm = 0u64;
    let kernel = measure(cfg, c.as_deref_mut(), || {
      let words = &pages[at & (INPUTS - 1)];
      at += 1;
      let r = (at as u32).wrapping_mul(0x9E37_79B9);
      let mask = asm::nonzero_words(black_box(words));
      if mask != 0 {
        sum_asm += u64::from(pick_bit(mask, r));
      }
    });
    black_box(sum_asm);
    print_row(
      csv,
      "pick word",
      &case,
      "two-pass",
      &two_pass,
      portable.median_ns,
    );
    print_row(
      csv,
      "pick word",
      &case,
      "portable",
      &portable,
      portable.median_ns,
    );
    print_row(csv, "pick word", &case, "asm", &kernel, portable.median_ns);
  }

  // `pack_blocks`: a cache that returns a claimed word packs the blocks
  // it still lists into a mask.
  for len in [1u8, 4, 16, 32, 64] {
    let lists: Vec<[Cell<u8>; 64]> = (0..64).map(|_| shuffled_list(&mut rng)).collect();
    let case = format!("{len} listed");
    let mut at = 0usize;
    let mut sum = 0u64;
    let portable = measure(cfg, c.as_deref_mut(), || {
      let list = &lists[at & 63];
      at += 1;
      sum ^= pack_blocks(black_box(list), black_box(len));
    });
    black_box(sum);
    let mut at = 0usize;
    let mut sum_asm = 0u64;
    let kernel = measure(cfg, c.as_deref_mut(), || {
      let list = &lists[at & 63];
      at += 1;
      sum_asm ^= asm::pack_blocks(black_box(list), black_box(len));
    });
    black_box(sum_asm);
    print_row(
      csv,
      "pack_blocks",
      &case,
      "portable",
      &portable,
      portable.median_ns,
    );
    print_row(
      csv,
      "pack_blocks",
      &case,
      "asm",
      &kernel,
      portable.median_ns,
    );
  }
}
