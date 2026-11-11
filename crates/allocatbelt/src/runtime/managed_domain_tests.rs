use super::{
  DomainError, DomainResource, DomainResources, MAX_STORAGE, OperationRequest, ResourceError,
  ResourceKind, ResourceLimits, ResourceScope, map_domain_error,
};
use crate::runtime::resource_domain::{ResourceDomain, TenantDomain};

const MEMORY: ResourceKind = ResourceKind::Memory;
const DISK: ResourceKind = ResourceKind::Disk;
const NETWORK: ResourceKind = ResourceKind::Network;

fn resources(memory: usize, disk: usize, network: usize) -> DomainResources {
  DomainResources::ZERO
    .with(DomainResource::Memory, memory)
    .with(DomainResource::Disk, disk)
    .with(DomainResource::Network, network)
    .with(DomainResource::Control, 1 << 16)
}

fn domain(memory: usize, disk: usize, network: usize, max_tenants: usize) -> ResourceDomain {
  ResourceDomain::new(resources(memory, disk, network), max_tenants)
    .unwrap_or_else(|error| panic!("test domain creation failed: {error}"))
}

fn tenant(domain: &ResourceDomain, memory: usize, disk: usize, network: usize) -> TenantDomain {
  domain
    .tenant(resources(memory, disk, network))
    .unwrap_or_else(|error| panic!("test tenant creation failed: {error}"))
}

fn scope(tenant: TenantDomain, memory: usize, disk: usize, network: usize) -> ResourceScope {
  ResourceScope::from_tenant(
    ResourceLimits {
      managed_memory: memory,
      disk_concurrent_ops: disk,
      network_concurrent_ops: network,
    },
    tenant,
  )
}

fn used(domain: &ResourceDomain, resource: DomainResource) -> usize {
  domain.snapshot().used.get(resource)
}

#[test]
fn global_memory_limit_covers_distinct_tenants_and_buffer_clones() {
  let domain = domain(64, 0, 0, 2);
  let left = scope(tenant(&domain, 64, 0, 0), 64, 0, 0);
  let right = scope(tenant(&domain, 64, 0, 0), 64, 0, 0);
  let first = left.try_alloc_zeroed(48).unwrap();
  assert_eq!(used(&domain, DomainResource::Memory), 48);
  assert_eq!(
    right.try_alloc_zeroed(17).map(drop),
    Err(ResourceError::Exhausted(MEMORY))
  );
  assert_eq!(right.snapshot().managed_memory, 0);

  let result = right.try_alloc_zeroed(16).unwrap();
  let retained = result.clone();
  drop(result);
  drop(right);
  assert_eq!(used(&domain, DomainResource::Memory), 64);
  drop(first);
  assert_eq!(used(&domain, DomainResource::Memory), 16);
  drop(retained);
  assert_eq!(used(&domain, DomainResource::Memory), 0);
}

#[test]
fn resize_reserves_old_and_replacement_peak_and_rolls_back_on_rejection() {
  let domain = domain(1 << 20, 0, 0, 1);
  let tenant = tenant(&domain, 1 << 20, 0, 0);
  tenant
    .set_limits(resources(159, 0, 0))
    .unwrap_or_else(|error| panic!("test tenant limit update failed: {error}"));
  let scope = scope(tenant.clone(), 1 << 20, 0, 0);
  let mut buffer = scope.try_alloc_zeroed(60).unwrap();
  buffer.get_mut().unwrap().fill(0x5a);

  assert_eq!(
    buffer.try_resize(100),
    Err(ResourceError::Exhausted(MEMORY))
  );
  assert_eq!(buffer.as_slice(), &[0x5a; 60]);
  assert_eq!(buffer.charged_bytes(), 60);
  assert_eq!(scope.snapshot().managed_memory, 60);
  assert_eq!(used(&domain, DomainResource::Memory), 60);

  tenant
    .set_limits(resources(1 << 20, 0, 0))
    .unwrap_or_else(|error| panic!("test tenant limit update failed: {error}"));
  buffer.try_resize(100).unwrap();
  assert_eq!(&buffer[..60], &[0x5a; 60]);
  assert!(buffer[60..].iter().all(|byte| *byte == 0));
  assert_eq!(scope.snapshot().managed_memory, buffer.charged_bytes());
  assert_eq!(
    used(&domain, DomainResource::Memory),
    buffer.charged_bytes()
  );
  drop(buffer);
  assert_eq!(used(&domain, DomainResource::Memory), 0);
}

#[test]
fn allocator_failure_releases_domain_reservation() {
  let domain = domain(usize::MAX, 0, 0, 1);
  let scope = scope(tenant(&domain, usize::MAX, 0, 0), usize::MAX, 0, 0);
  assert_eq!(
    scope.try_alloc_zeroed(MAX_STORAGE).map(drop),
    Err(ResourceError::OutOfMemory)
  );
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(used(&domain, DomainResource::Memory), 0);
}

#[test]
fn domain_disk_and_network_admission_is_atomic_and_held_by_permits() {
  let domain = domain(0, 1, 1, 2);
  let left = scope(tenant(&domain, 0, 1, 1), 0, 1, 1);
  let right = scope(tenant(&domain, 0, 1, 1), 0, 1, 1);
  let first = left
    .try_acquire(OperationRequest {
      disk: 1,
      network: 1,
    })
    .unwrap();
  assert_eq!(
    right
      .try_acquire(OperationRequest {
        disk: 1,
        network: 1,
      })
      .map(drop),
    Err(ResourceError::Exhausted(DISK))
  );
  assert_eq!(
    (right.snapshot().disk_ops, right.snapshot().network_ops),
    (0, 0)
  );
  assert_eq!(used(&domain, DomainResource::Disk), 1);
  assert_eq!(used(&domain, DomainResource::Network), 1);

  drop(first);
  let next = right
    .try_acquire(OperationRequest {
      disk: 1,
      network: 1,
    })
    .unwrap();
  drop(next);
  assert_eq!(used(&domain, DomainResource::Disk), 0);
  assert_eq!(used(&domain, DomainResource::Network), 0);
}

#[test]
fn closing_rejects_new_admission_but_retained_buffer_owns_its_generation() {
  let domain = domain(32, 1, 1, 1);
  let tenant = tenant(&domain, 32, 1, 1);
  let scope = scope(tenant.clone(), 64, 1, 1);
  let mut buffer = scope.try_alloc_zeroed(16).unwrap();
  tenant.close();

  assert_eq!(
    scope.try_alloc_zeroed(1).map(drop),
    Err(ResourceError::Closed)
  );
  assert_eq!(buffer.try_resize(32), Err(ResourceError::Closed));
  let result_clone = buffer.clone();
  assert_eq!(buffer.try_resize(32), Err(ResourceError::Shared));
  assert_eq!(
    scope.try_acquire(OperationRequest::default()).map(drop),
    Err(ResourceError::Closed)
  );
  assert_eq!(buffer.as_slice(), &[0; 16]);
  assert_eq!(scope.snapshot().managed_memory, 16);
  assert_eq!(used(&domain, DomainResource::Memory), 16);
  assert_eq!(
    domain.tenant(resources(32, 1, 1)).err(),
    Some(DomainError::TenantsFull)
  );

  drop(buffer);
  assert_eq!(used(&domain, DomainResource::Memory), 16);
  drop(result_clone);
  assert_eq!(used(&domain, DomainResource::Memory), 0);
  drop(scope);
  drop(tenant);
  assert!(domain.tenant(resources(32, 1, 1)).is_ok());
}

#[test]
fn cloned_scope_keeps_tenant_admission_open_after_the_original_drops() {
  let domain = domain(8, 0, 0, 1);
  let tenant = tenant(&domain, 8, 0, 0);
  let original = scope(tenant.clone(), 8, 0, 0);
  let retained_scope = original.clone();
  drop(original);
  drop(tenant);

  let buffer = retained_scope.try_alloc_zeroed(8).unwrap();
  assert_eq!(used(&domain, DomainResource::Memory), 8);
  drop(buffer);
  drop(retained_scope);
  assert!(domain.tenant(resources(8, 0, 0)).is_ok());
}

#[test]
fn zero_operation_permit_keeps_its_tenant_generation_until_drop() {
  let domain = domain(0, 0, 0, 1);
  let tenant = tenant(&domain, 0, 0, 0);
  let scope = scope(tenant.clone(), 0, 0, 0);
  let permit = scope.try_acquire(OperationRequest::default()).unwrap();
  drop(scope);
  drop(tenant);

  assert_eq!(
    domain.tenant(resources(0, 0, 0)).err(),
    Some(DomainError::TenantsFull)
  );
  drop(permit);
  assert!(domain.tenant(resources(0, 0, 0)).is_ok());
}

#[test]
fn empty_bound_buffers_keep_the_tenant_and_zero_growth_requires_no_charge() {
  let domain = domain(1, 0, 0, 1);
  let tenant = tenant(&domain, 1, 0, 0);
  let scope = scope(tenant.clone(), 1, 0, 0);
  let mut empty = scope.try_alloc_zeroed(0).unwrap();
  assert_eq!(empty.charged_bytes(), 0);
  assert_eq!(used(&domain, DomainResource::Memory), 0);
  assert_eq!(empty.try_resize(0), Ok(()));

  tenant.close();
  assert_eq!(empty.try_resize(0), Ok(()));
  assert_eq!(empty.try_resize(1), Err(ResourceError::Closed));
  assert_eq!(empty.charged_bytes(), 0);
  drop(empty);
  drop(scope);
  drop(tenant);
  assert!(domain.tenant(resources(1, 0, 0)).is_ok());
}

#[test]
fn domain_errors_map_without_silent_fallback() {
  assert_eq!(map_domain_error(DomainError::Closed), ResourceError::Closed);
  assert_eq!(
    map_domain_error(DomainError::Exhausted(DomainResource::Control)),
    ResourceError::DomainControlExhausted
  );
  assert_eq!(
    map_domain_error(DomainError::Exhausted(DomainResource::Cpu)),
    ResourceError::DomainAdmission
  );
  assert_eq!(
    map_domain_error(DomainError::Exhausted(DomainResource::Network)),
    ResourceError::Exhausted(NETWORK)
  );
  assert_eq!(
    ResourceError::DomainControlExhausted.to_string(),
    "the resource domain has no free control reservation capacity"
  );
}
