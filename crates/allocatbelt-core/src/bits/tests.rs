use super::*;

fn naive(free: u64, n: u32) -> Option<u32> {
  (0..=64u32.saturating_sub(n)).find(|&i| (i..i + n).all(|b| free >> b & 1 == 1))
}

#[test]
fn run_matches_naive() {
  let samples = [
    0u64,
    u64::MAX,
    0x0F0F_0F0F_0F0F_0F0F,
    0x8000_0000_0000_0001,
    0xFFFF_0000_FFFF_FFF0,
    0x7FFF_FFFF_FFFF_FFFE,
    0x0000_00FF_FF00_0000,
  ];
  for &f in &samples {
    for n in 1..=64 {
      assert_eq!(find_run(f, n), naive(f, n), "free={f:#x} n={n}");
    }
  }
}

#[test]
fn out_of_range_lengths_have_no_run() {
  for f in [0, 1, u64::MAX] {
    assert_eq!(find_run(f, 0), None, "free={f:#x}");
    assert_eq!(find_run(f, 65), None, "free={f:#x}");
    assert_eq!(find_run_aligned(f, 0, 1), None, "free={f:#x}");
  }
}

#[test]
fn strides() {
  for shift in 0..=6 {
    let step = 1u32 << shift;
    let naive = (0..64).step_by(step as usize).fold(0u64, |m, i| m | 1 << i);
    assert_eq!(stride_mask(step), naive, "step {step}");
  }
}

#[test]
fn masks() {
  assert_eq!(run_mask(0, 64), u64::MAX);
  assert_eq!(run_mask(3, 2), 0b11000);
  assert_eq!(run_mask(63, 1), 1 << 63);
}

fn naive_aligned(free: u64, n: u32, step: u32) -> Option<u32> {
  (0..=64u32.saturating_sub(n))
    .step_by(step as usize)
    .find(|&i| (i..i + n).all(|b| free >> b & 1 == 1))
}

proptest::proptest! {
    #[test]
    fn run_prop(f: u64, n in 1u32..=64) {
        proptest::prop_assert_eq!(find_run(f, n), naive(f, n));
    }

    #[test]
    fn aligned_run_prop(f: u64, n in 1u32..=64, shift in 0u32..=6) {
        let step = 1 << shift;
        proptest::prop_assert_eq!(find_run_aligned(f, n, step), naive_aligned(f, n, step));
    }
}

#[test]
fn pick_wraps() {
  assert_eq!(pick_bit(0b1001, 0), 0);
  assert_eq!(pick_bit(0b1001, 1), 3);
  assert_eq!(pick_bit(0b1001, 4), 0);
  assert_eq!(pick_bit(1 << 63, 17), 63);
}

proptest::proptest! {
    #[test]
    fn pick_prop(m in 1u64.., r: u32) {
        let i = pick_bit(m, r);
        proptest::prop_assert!(m >> i & 1 == 1);
        // No set bit lies between the start and the pick.
        let start = r & 63;
        let skipped = (0..(i + 64 - start) % 64).all(|d| m >> ((start + d) % 64) & 1 == 0);
        proptest::prop_assert!(skipped);
    }
}
