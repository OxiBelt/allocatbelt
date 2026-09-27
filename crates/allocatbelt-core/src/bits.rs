//! Bit-twiddling helpers. They compile to `tzcnt`/`popcnt`/`lzcnt` where the
//! target supports them (e.g. `-C target-feature=+bmi1,+popcnt,+lzcnt` or
//! `-C target-cpu=x86-64-v3`) and stay entirely in safe Rust.

/// Index of the first run of `n` consecutive set bits in `free`, if any.
///
/// Uses the doubling trick: after each step bit `i` of `m` is set iff bits
/// `i..i + k` of `free` are all set, so it needs only `O(log n)` shifts.
#[must_use]
pub const fn find_run(free: u64, n: u32) -> Option<u32> {
    if n == 0 || n > 64 {
        return None;
    }
    if n == 64 {
        return if free == u64::MAX { Some(0) } else { None };
    }
    let mut m = free;
    let mut k = 1;
    while k < n {
        let s = if k < n - k { k } else { n - k };
        m &= m >> s;
        k += s;
    }
    if m == 0 {
        None
    } else {
        Some(m.trailing_zeros())
    }
}

/// Mask with bits `start..start + n` set (`n` in `1..=64`).
#[must_use]
pub const fn run_mask(start: u32, n: u32) -> u64 {
    let ones = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
    ones << start
}

#[cfg(test)]
mod tests {
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
    fn masks() {
        assert_eq!(run_mask(0, 64), u64::MAX);
        assert_eq!(run_mask(3, 2), 0b11000);
        assert_eq!(run_mask(63, 1), 1 << 63);
    }

    proptest::proptest! {
        #[test]
        fn run_prop(f: u64, n in 1u32..=64) {
            proptest::prop_assert_eq!(find_run(f, n), naive(f, n));
        }
    }
}
