//! Models the real ledger's reservation, rollback and release transitions
//! behind a Loom mutex. The production Arc/Vec ownership and destructors are
//! covered by native tests; this model does not instrument those wrappers.

use loom::sync::{Arc, Mutex};
use loom::thread;

use super::{Ledger, OperationRequest, ResourceLimits};

#[test]
fn loom_multi_resource_reservations_remain_atomic() {
  loom::model(|| {
    let ledger = Arc::new(Mutex::new(Ledger::new(ResourceLimits {
      managed_memory: 0,
      disk_concurrent_ops: 1,
      network_concurrent_ops: 1,
    })));
    let request = OperationRequest {
      disk: 1,
      network: 1,
    };
    let workers: Vec<_> = (0..2)
      .map(|_| {
        let ledger = Arc::clone(&ledger);
        thread::spawn(move || {
          let admitted = {
            let mut state = ledger.lock().unwrap();
            let before = state.snapshot();
            let admitted = state.acquire_ops(request).is_ok();
            if !admitted {
              assert_eq!(state.snapshot(), before);
            }
            let after = state.snapshot();
            assert_eq!(after.disk_ops, after.network_ops);
            assert!(after.disk_ops <= 1);
            admitted
          };
          thread::yield_now();
          if admitted {
            assert!(ledger.lock().unwrap().release_ops(request));
          }
        })
      })
      .collect();
    for worker in workers {
      worker.join().unwrap();
    }
    let state = ledger.lock().unwrap().snapshot();
    assert_eq!((state.disk_ops, state.network_ops), (0, 0));
  });
}

#[test]
fn loom_peak_growth_competes_with_another_reservation() {
  loom::model(|| {
    let ledger = Arc::new(Mutex::new(Ledger::new(ResourceLimits {
      managed_memory: 3,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    })));
    assert!(ledger.lock().unwrap().reserve_memory(1, 1).is_ok());
    let other = {
      let ledger = Arc::clone(&ledger);
      thread::spawn(move || {
        let admitted = {
          let mut state = ledger.lock().unwrap();
          let before = state.snapshot();
          let admitted = state.reserve_memory(1, 1).is_ok();
          if !admitted {
            assert_eq!(state.snapshot(), before);
          }
          assert!(state.snapshot().managed_memory <= 3);
          admitted
        };
        thread::yield_now();
        if admitted {
          assert!(ledger.lock().unwrap().release_memory(1));
        }
      })
    };
    let replacement = {
      let mut state = ledger.lock().unwrap();
      let before = state.snapshot();
      let admitted = state.reserve_memory(2, 2).is_ok();
      if !admitted {
        assert_eq!(state.snapshot(), before);
      }
      assert!(state.snapshot().managed_memory <= 3);
      admitted
    };
    thread::yield_now();
    // The caller frees its old storage, then its replacement if admitted.
    assert!(ledger.lock().unwrap().release_memory(1));
    if replacement {
      assert!(ledger.lock().unwrap().release_memory(2));
    }
    other.join().unwrap();
    assert_eq!(ledger.lock().unwrap().snapshot().managed_memory, 0);
  });
}
