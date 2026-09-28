//! The background purge thread returns freed memory without further
//! allocator calls. A separate test binary, so no other test allocates
//! meanwhile.

use std::time::{Duration, Instant};

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

fn rss_kib() -> u64 {
  let status = std::fs::read_to_string("/proc/self/status").unwrap();
  let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
  line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn idle_memory_is_returned_by_the_purge_thread() {
  GLOBAL.set_purge_delay(Duration::from_millis(100));
  assert!(GLOBAL.start_purge_thread().unwrap());
  assert!(!GLOBAL.start_purge_thread().unwrap(), "started twice");
  // 20 MiB of page runs, below the 32 MiB dirty budget, fully touched.
  let bufs: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8 | 1; 1 << 20]).collect();
  let peak = rss_kib();
  drop(bufs);
  assert!(
    GLOBAL.dirty_bytes() >= 19 << 20,
    "freed pages stay resident at first"
  );
  // Nothing else allocates or frees from here on; only the thread can purge.
  let deadline = Instant::now() + Duration::from_secs(10);
  while GLOBAL.dirty_bytes() != 0 && Instant::now() < deadline {
    std::thread::sleep(Duration::from_millis(20));
  }
  assert_eq!(GLOBAL.dirty_bytes(), 0);
  let after = rss_kib();
  assert!(
    peak - after >= 15 << 10,
    "RSS went from {peak} KiB to {after} KiB only"
  );
}
