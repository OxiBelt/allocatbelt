use super::*;

#[test]
fn table_shape() {
  assert_eq!(size(0), 16);
  assert_eq!(size(7), 128);
  assert_eq!(size(8), 160);
  assert_eq!(size(NUM_CLASSES - 1), SMALL_MAX);
  for c in 1..NUM_CLASSES {
    assert!(size(c) > size(c - 1));
    assert_eq!(size(c) % MIN_ALIGN, 0);
    assert!(bitmap_words(c) <= MAX_BITMAP_WORDS);
  }
  for c in 0..NUM_CLASSES {
    assert_eq!(capacity(c), PAGE_SIZE / size(c), "class {c}");
    assert_eq!(bitmap_words(c), capacity(c).div_ceil(64), "class {c}");
  }
  for k in 4..=13 {
    let p = 1usize << k;
    assert_eq!(size(class_of(p)), p, "power of two {p} must be a class");
  }
}

#[test]
fn class_for_is_tight() {
  for shift in 0..=16 {
    let align = 1usize << shift;
    for requested in 0..=SMALL_MAX {
      let naive = (0..NUM_CLASSES)
        .find(|&c| size(c) >= requested.max(align) && size(c).is_multiple_of(align));
      assert_eq!(
        class_for(requested, align),
        naive,
        "size {requested} align {align}"
      );
    }
  }
  assert_eq!(class_for(5000, 32), Some(class_of(5120)));
  assert_eq!(class_for(3000, 1024), Some(class_of(3072)));
  assert_eq!(class_for(8, 1 << 17), None);
  assert_eq!(class_for(SMALL_MAX + 1, 8), None);
}

#[test]
fn class_for_rounding_boundaries() {
  for (requested, align) in [
    (0, 1),
    (1, MIN_ALIGN),
    (127, MIN_ALIGN),
    (128, MIN_ALIGN),
    (5000, 32),
    (8191, 32),
    (SMALL_MAX, MIN_ALIGN),
    (0, PAGE_SIZE),
    (1, PAGE_SIZE),
    (SMALL_MAX, PAGE_SIZE),
    (0, PAGE_SIZE + 1),
    (SMALL_MAX + 1, MIN_ALIGN),
    (usize::MAX, MIN_ALIGN),
    (8, usize::MAX),
  ] {
    let expected = (align.is_power_of_two() && align <= PAGE_SIZE && requested <= SMALL_MAX)
      .then(|| {
        (0..NUM_CLASSES).find(|&c| size(c) >= requested.max(align) && size(c).is_multiple_of(align))
      })
      .flatten();
    assert_eq!(
      class_for(requested, align),
      expected,
      "size {requested} align {align}"
    );
  }
}

#[test]
fn class_of_is_tight() {
  for s in 0..=SMALL_MAX {
    let c = class_of(s);
    assert!(size(c) >= s.max(1), "size {s}");
    if c > 0 {
      assert!(size(c - 1) < s, "size {s} not in smallest class");
    }
  }
}

#[test]
fn block_index_divides() {
  for c in 0..NUM_CLASSES {
    for off in 0..PAGE_SIZE {
      let want = (off % size(c) == 0 && off / size(c) < capacity(c)).then(|| off / size(c));
      assert_eq!(block_index(c, off), want, "class {c} offset {off}");
    }
  }
}
