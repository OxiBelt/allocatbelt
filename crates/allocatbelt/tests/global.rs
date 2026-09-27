//! Runs std collections and threads with allocatbelt as the global allocator.

#![allow(unsafe_code, reason = "tests exercise the raw GlobalAlloc API")]

use std::alloc::{GlobalAlloc, Layout};
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

#[test]
fn collections() {
    let mut v: Vec<u64> = (0..100_000).collect();
    v.extend(0..1_000_000);
    assert_eq!(
        v.iter().sum::<u64>(),
        (0..100_000u64).sum::<u64>() + (0..1_000_000u64).sum::<u64>()
    );
    let m: HashMap<String, Vec<u8>> = (0..10_000)
        .map(|i| (format!("key-{i}"), vec![i as u8; i % 300]))
        .collect();
    assert_eq!(m["key-299"].len(), 299);
    let b: BTreeMap<u32, Box<[u8]>> = (0..5_000)
        .map(|i| (i, vec![1; 100].into_boxed_slice()))
        .collect();
    assert_eq!(b.len(), 5_000);
    let big = vec![7u8; 64 << 20];
    assert!(big.iter().all(|&x| x == 7));
}

#[test]
fn zeroed_and_realloc() {
    for &size in &[1usize, 100, 8192, 70_000, 5 << 20] {
        let layout = Layout::from_size_align(size, 8).unwrap();
        // SAFETY: non-zero layout; the block is freed below with the same layout.
        let p = unsafe { GLOBAL.alloc_zeroed(layout) };
        assert!(!p.is_null());
        // SAFETY: `p` is valid for `size` bytes.
        let s = unsafe { std::slice::from_raw_parts_mut(p, size) };
        assert!(s.iter().all(|&x| x == 0));
        s.fill(0xAB);
        // SAFETY: `p` came from `alloc_zeroed` with `layout`.
        let q = unsafe { GLOBAL.realloc(p, layout, size * 3) };
        assert!(!q.is_null());
        // SAFETY: the first `size` bytes were preserved by realloc.
        let s = unsafe { std::slice::from_raw_parts(q, size) };
        assert!(s.iter().all(|&x| x == 0xAB));
        // SAFETY: `q` is live with size `size * 3`.
        unsafe { GLOBAL.dealloc(q, Layout::from_size_align(size * 3, 8).unwrap()) };
    }
}

#[test]
fn over_aligned() {
    for shift in 4..=22 {
        let layout = Layout::from_size_align(24, 1 << shift).unwrap();
        let p = GLOBAL.allocate(layout).expect("alloc");
        assert_eq!(p.as_ptr().addr() % (1 << shift), 0);
        // SAFETY: allocated above with this layout.
        unsafe { GLOBAL.dealloc(p.as_ptr(), layout) };
    }
}

#[test]
fn producer_consumer_threads() {
    let (tx, rx) = mpsc::sync_channel::<Vec<Box<[u8]>>>(64);
    let producers: Vec<_> = (0..8)
        .map(|t| {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for i in 0..2_000 {
                    let batch = (0..16)
                        .map(|j| vec![t as u8; (i * 31 + j * 17) % 3000 + 1].into_boxed_slice())
                        .collect();
                    tx.send(batch).unwrap();
                }
            })
        })
        .collect();
    drop(tx);
    let mut total = 0usize;
    for batch in rx {
        total += batch.iter().map(|b| b.len()).sum::<usize>();
    }
    for p in producers {
        p.join().unwrap();
    }
    assert!(total > 0);
}
