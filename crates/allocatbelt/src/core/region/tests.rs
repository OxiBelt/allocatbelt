use super::*;

use proptest::prelude::*;

#[test]
fn align_up_rounds_to_powers_of_two_only() {
  assert_eq!(align_up(0, 1), Some(0));
  assert_eq!(align_up(1, 8), Some(8));
  assert_eq!(align_up(8, 8), Some(8));
  assert_eq!(align_up(9, 4096), Some(4096));
  assert_eq!(align_up(usize::MAX - 6, 8), None);
  assert_eq!(align_up(usize::MAX, 1), Some(usize::MAX));
  assert_eq!(align_up(5, 0), None);
  assert_eq!(align_up(5, 3), None);
}

#[test]
fn bump_fits_exactly_and_refuses_one_byte_more() {
  assert_eq!(bump(0, 16, 16, 8), Some((0, 16)));
  assert_eq!(bump(0, 16, 17, 8), None);
  assert_eq!(bump(1, 16, 8, 8), Some((8, 16)));
  assert_eq!(bump(1, 16, 9, 8), None);
  // Zero-sized pieces take no room but are aligned, also at the end.
  assert_eq!(bump(16, 16, 0, 8), Some((16, 16)));
  assert_eq!(bump(15, 16, 0, 8), Some((16, 16)));
  assert_eq!(bump(17, 20, 0, 8), None);
  // Overflow near the top of the address space.
  assert_eq!(bump(usize::MAX - 3, usize::MAX, 8, 1), None);
  assert_eq!(bump(usize::MAX - 3, usize::MAX, 1, 16), None);
  assert_eq!(bump(0, usize::MAX, usize::MAX, 1), Some((0, usize::MAX)));
}

#[test]
fn standard_chunks_are_clamped_and_rounded() {
  assert_eq!(standard_chunk(0), MIN_CHUNK);
  assert_eq!(standard_chunk(MIN_CHUNK + 1), MIN_CHUNK + MIN_CHUNK_ALIGN);
  assert_eq!(standard_chunk(DEFAULT_CHUNK), DEFAULT_CHUNK);
  assert_eq!(standard_chunk(usize::MAX), MAX_CHUNK);
}

#[test]
fn own_chunks_start_the_request_at_their_base() {
  assert_eq!(own_chunk(1, 1), Some((16, 16)));
  assert_eq!(own_chunk(0, 1), Some((16, 16)));
  assert_eq!(own_chunk(100, 4096), Some((112, 4096)));
  assert_eq!(own_chunk(0, 1 << 20), Some((1 << 20, 1 << 20)));
  assert_eq!(own_chunk(usize::MAX, 1), None);
}

#[test]
fn resets_keep_standard_chunks_up_to_the_limit_only() {
  assert!(keep_on_reset(true, 64, 0, 64));
  assert!(!keep_on_reset(true, 64, 1, 64));
  assert!(!keep_on_reset(false, 64, 0, usize::MAX));
  assert!(!keep_on_reset(true, 1, usize::MAX, usize::MAX));
  assert!(keep_on_reset(true, 0, 0, 0));
  assert!(within_limit(10, 6, 16));
  assert!(!within_limit(10, 7, 16));
  assert!(!within_limit(usize::MAX, 1, usize::MAX));
}

proptest! {
  /// A piece is aligned, inside `[cursor, end]`, and the next piece starts
  /// at or after its end: successive pieces never overlap.
  #[test]
  fn bumps_are_aligned_in_bounds_and_disjoint(
    base in 0usize..1 << 40,
    len in 0usize..1 << 20,
    reqs in proptest::collection::vec((0usize..5000, 0u32..13), 1..40),
  ) {
    let end = base + len;
    let mut cursor = base;
    for (size, shift) in reqs {
      let align = 1usize << shift;
      match bump(cursor, end, size, align) {
        Some((start, next)) => {
          prop_assert_eq!(start % align, 0);
          prop_assert!(start >= cursor && next == start + size && next <= end);
          cursor = next;
        }
        None => {
          // Refused only when it would not fit.
          let start = align_up(cursor, align).unwrap();
          prop_assert!(start + size > end);
        }
      }
    }
  }

  /// What `fits_standard` accepts fits an empty standard chunk at any base
  /// aligned to `MIN_CHUNK_ALIGN`.
  #[test]
  fn standard_fits_fit_every_chunk_base(
    size in 0usize..1 << 17,
    shift in 0u32..17,
    chunk in MIN_CHUNK..1 << 17,
    base in (0usize..1 << 30).prop_map(|b| b * MIN_CHUNK_ALIGN),
  ) {
    let chunk = standard_chunk(chunk);
    let align = 1usize << shift;
    if fits_standard(size, align, chunk) {
      prop_assert!(bump(base, base + chunk, size, align).is_some());
    }
  }

  /// A chunk of its own holds its request at its base.
  #[test]
  fn own_chunks_hold_their_request(size in 0usize..1 << 30, shift in 0u32..23) {
    let align = 1usize << shift;
    let (cap, chunk_align) = own_chunk(size, align).unwrap();
    prop_assert!(chunk_align >= align && chunk_align >= MIN_CHUNK_ALIGN);
    prop_assert!(cap >= size && cap > 0 && cap % MIN_CHUNK_ALIGN == 0);
    prop_assert_eq!(bump(0, cap, size, align), Some((0, size)));
  }
}
