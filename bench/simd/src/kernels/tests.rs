//! Every detected variant must agree with the scalar baseline, at every
//! length the benchmark uses and at the awkward ones around vector widths.

use super::Families;

/// xorshift64*, so the tests need no dependency.
struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 >> 12;
    self.0 ^= self.0 << 25;
    self.0 ^= self.0 >> 27;
    self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
  }

  /// Words that are zero with probability `1 / zero_one_in`.
  fn words(&mut self, n: usize, zero_one_in: u64) -> Vec<u64> {
    (0..n)
      .map(|_| {
        let w = self.next();
        if w.is_multiple_of(zero_one_in) { 0 } else { w }
      })
      .collect()
  }
}

const LENGTHS: [usize; 16] = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 256];

#[test]
fn nonzero_variants_agree() {
  let f = Families::detected();
  let mut rng = Rng(1);
  for n in LENGTHS {
    for zero_one_in in [1, 2, 8, u64::MAX] {
      let words = rng.words(n, zero_one_in);
      let mut want = vec![0u64; n.div_ceil(64)];
      (f.nonzero[0].get())(&words, &mut want);
      for v in &f.nonzero {
        let mut got = vec![u64::MAX; n.div_ceil(64)];
        (v.get())(&words, &mut got);
        assert_eq!(got, want, "{} n={n}", v.name());
      }
    }
  }
}

#[test]
fn popcount_variants_agree() {
  let f = Families::detected();
  let mut rng = Rng(2);
  for n in LENGTHS {
    let words = rng.words(n, 4);
    let want: u64 = words.iter().map(|w| u64::from(w.count_ones())).sum();
    for v in &f.popcount {
      assert_eq!((v.get())(&words), want, "{} n={n}", v.name());
    }
  }
}

#[test]
fn age_variants_agree() {
  let f = Families::detected();
  let mut rng = Rng(3);
  for _ in 0..200 {
    let mut since = [0u64; 64];
    for s in &mut since {
      // Small epochs, plus the extremes, so that comparisons tie often.
      *s = match rng.next() % 8 {
        0 => 0,
        1 => u64::MAX,
        _ => rng.next() % 16,
      };
    }
    let candidates = rng.next();
    for cutoff in [0, 7, 8, u64::MAX - 1, u64::MAX, rng.next()] {
      let want = (f.age[0].get())(&since, candidates, cutoff);
      for v in &f.age {
        assert_eq!(
          (v.get())(&since, candidates, cutoff),
          want,
          "{} cutoff={cutoff}",
          v.name()
        );
      }
    }
  }
}

#[test]
fn zero_and_copy_variants_agree() {
  let f = Families::detected();
  let mut rng = Rng(4);
  let src: Vec<u8> = (0..70_000).map(|_| rng.next() as u8).collect();
  // Every length up to a few vectors, then larger ones, at every offset
  // within a vector so the unaligned heads and tails are covered.
  let lens = (0..=300).chain([1000, 4096, 8192, 65_536]);
  for len in lens {
    for off in [0, 1, 7, 31, 33] {
      for v in &f.zero {
        let mut buf = vec![0xa5u8; len + off + 1];
        (v.get())(&mut buf[off..off + len]);
        assert!(
          buf[off..off + len].iter().all(|&b| b == 0),
          "{} len={len}",
          v.name()
        );
        assert_eq!(buf[..off], vec![0xa5; off][..], "{} wrote before", v.name());
        assert_eq!(buf[off + len], 0xa5, "{} wrote past the end", v.name());
      }
      for v in &f.copy {
        let mut dst = vec![0u8; len + off + 1];
        (v.get())(&mut dst[off..off + len], &src[1..=len]);
        assert_eq!(dst[off..off + len], src[1..=len], "{} len={len}", v.name());
        assert_eq!(dst[off + len], 0, "{} wrote past the end", v.name());
      }
    }
  }
}

#[test]
fn every_family_has_a_baseline() {
  let f = Families::detected();
  assert_eq!(f.nonzero[0].name(), "scalar");
  assert_eq!(f.popcount[0].name(), "scalar");
  assert_eq!(f.age[0].name(), "scalar-sparse");
  assert_eq!(f.zero[0].name(), "memset");
  assert_eq!(f.copy[0].name(), "memcpy");
}
