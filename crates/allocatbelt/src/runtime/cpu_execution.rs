//! Thread-local identities for user code that currently owns bounded CPU
//! tickets.
//!
//! Reentrant admission and joins into a domain whose only CPU ticket is held
//! by the current stack must fail instead of waiting for the suspended call
//! to release it. The fixed TLS table avoids allocation on poll and closure
//! paths. Overflow is conservative: it marks every domain active until those
//! overflowed guards leave.

use std::cell::RefCell;

use crate::runtime::resource_domain::DomainIdentity;

const ACTIVE_DOMAIN_CAPACITY: usize = 32;

struct ActiveDomains {
  domains: [Option<DomainIdentity>; ACTIVE_DOMAIN_CAPACITY],
  overflow: usize,
  overflow_saturated: bool,
}

impl ActiveDomains {
  const fn new() -> Self {
    Self {
      domains: [const { None }; ACTIVE_DOMAIN_CAPACITY],
      overflow: 0,
      overflow_saturated: false,
    }
  }
}

thread_local! {
  static ACTIVE: RefCell<ActiveDomains> = const { RefCell::new(ActiveDomains::new()) };
}

pub(crate) struct CpuExecutionGuard {
  slot: Option<usize>,
  overflow: bool,
}

impl CpuExecutionGuard {
  pub(crate) fn enter(domain: Option<DomainIdentity>) -> Self {
    let Some(domain) = domain else {
      return Self {
        slot: None,
        overflow: false,
      };
    };
    let entered = ACTIVE.try_with(|active| {
      let mut active = active.borrow_mut();
      if let Some(index) = active.domains.iter().position(Option::is_none) {
        active.domains[index] = Some(domain);
        (Some(index), false)
      } else {
        if let Some(next) = active.overflow.checked_add(1) {
          active.overflow = next;
        } else {
          active.overflow_saturated = true;
        }
        (None, true)
      }
    });
    match entered {
      Ok((slot, overflow)) => Self { slot, overflow },
      // During TLS teardown, active_for_domain also fails closed.
      Err(_) => Self {
        slot: None,
        overflow: false,
      },
    }
  }
}

impl Drop for CpuExecutionGuard {
  fn drop(&mut self) {
    if self.slot.is_none() && !self.overflow {
      return;
    }
    let slot = self.slot;
    let overflow = self.overflow;
    let removed = ACTIVE.try_with(|active| {
      let mut active = active.borrow_mut();
      if let Some(index) = slot {
        active.domains[index].take()
      } else if overflow {
        if !active.overflow_saturated {
          active.overflow = active.overflow.saturating_sub(1);
        }
        None
      } else {
        None
      }
    });
    let _ = removed.ok().flatten();
  }
}

pub(crate) fn active_for_domain(domain: &DomainIdentity) -> bool {
  ACTIVE
    .try_with(|active| {
      let active = active.borrow();
      active.overflow_saturated
        || active.overflow != 0
        || active
          .domains
          .iter()
          .flatten()
          .any(|current| current == domain)
    })
    // A caller during TLS teardown cannot prove that the suspended CPU
    // owner has left, so reject conservatively.
    .unwrap_or(true)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  fn identity() -> DomainIdentity {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 1)
      .with(DomainResource::Tasks, 2)
      .with(DomainResource::Control, 4096);
    let domain = ResourceDomain::new(ceiling, 1).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
      .unwrap()
      .domain_identity()
  }

  #[test]
  fn activity_matches_domain_identity_and_removes_out_of_order_guards() {
    let first = identity();
    let second = identity();
    let first_guard = CpuExecutionGuard::enter(Some(first));
    let second_guard = CpuExecutionGuard::enter(Some(second));
    assert!(active_for_domain(&first));
    assert!(active_for_domain(&second));

    drop(first_guard);
    assert!(!active_for_domain(&first));
    assert!(active_for_domain(&second));
    drop(second_guard);
    assert!(!active_for_domain(&second));
  }

  #[test]
  fn activity_overflow_rejects_conservatively_and_clears_after_release() {
    let active = identity();
    let unrelated = identity();
    let guards: Vec<_> = (0..=ACTIVE_DOMAIN_CAPACITY)
      .map(|_| CpuExecutionGuard::enter(Some(active)))
      .collect();
    assert!(active_for_domain(&active));
    assert!(active_for_domain(&unrelated));

    drop(guards);
    assert!(!active_for_domain(&active));
    assert!(!active_for_domain(&unrelated));
  }
}
