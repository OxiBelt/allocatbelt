//! The start-up probe of the platform contract (docs/platform.md).

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

#[test]
fn probe_ran_before_the_first_allocation() {
  let v = vec![1u8; 4096];
  let caps = GLOBAL
    .platform()
    .expect("the allocator initialised without its arena");
  assert!(
    caps.kernel.is_some(),
    "unparseable kernel release: {caps:?}"
  );
  assert_eq!(v.iter().map(|&b| usize::from(b)).sum::<usize>(), 4096);
}
