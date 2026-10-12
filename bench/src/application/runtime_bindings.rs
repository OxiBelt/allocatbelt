//! One owning resource domain and matched fixed I/O policy for an application run.

use allocatbelt::runtime::byte_rate::{ByteRateConfig, ByteRateLimit};
use allocatbelt::runtime::cpu_gate::CpuGate;
use allocatbelt::runtime::driver::{IoBindings, MultiThreadDriver};
use allocatbelt::runtime::fs::BlockingByteIo;
use allocatbelt::runtime::io::{AsyncRead, AsyncWrite};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::rate_io::RateLimitedIo;
use allocatbelt::runtime::resource_domain::{
  DomainReservation, DomainResource, DomainResources, ResourceDomain, TenantDomain,
};
use allocatbelt::runtime::time::TimerDriver;

use super::{Workload, resource_limits};

pub(crate) const APPLICATION_TASK_CEILING: usize = 64;
pub(crate) const CPU_WAITER_CEILING: usize = APPLICATION_TASK_CEILING;
// CPU-gate waiter leases consume 64 fixed slots. The remaining 192 slots
// cover the owning async pool, filesystem pool, and bounded service roles.
const DOMAIN_WAITER_CEILING: usize = 256;
const DOMAIN_CONTROL_CEILING: usize = 64 * 1024 * 1024;
const RATE_BYTES_PER_SECOND: u64 = 16 * 1024 * 1024 * 1024;
const RATE_BURST_BYTES: usize = 64 * 1024;
const RATE_RESERVATIONS: usize = 64;
const RATE_TIMER_REGISTRATIONS: usize = 256;

fn fixed_rate_config() -> ByteRateConfig {
  ByteRateConfig {
    bytes_per_second: RATE_BYTES_PER_SECOND,
    burst_bytes: RATE_BURST_BYTES,
    max_reservations: RATE_RESERVATIONS,
  }
}

/// Pre-runtime owner shared by both executor variants.
pub(crate) struct ApplicationDomain {
  domain: ResourceDomain,
  tenant: TenantDomain,
  cpu_gate: CpuGate,
  local_limits: ResourceLimits,
  domain_limits: DomainResources,
  fixed_global_control_baseline: usize,
}

impl ApplicationDomain {
  pub(crate) fn new(workload: Workload, workers: usize) -> Result<Self, String> {
    if workers == 0 || workers > 4 {
      return Err("application runtime requires a frozen two- or four-worker bound".into());
    }
    let local_limits = resource_limits(workload);
    let domain_limits = DomainResources::ZERO
      .with(DomainResource::Cpu, workers)
      .with(DomainResource::Memory, local_limits.managed_memory)
      .with(DomainResource::Disk, local_limits.disk_concurrent_ops)
      .with(DomainResource::Network, local_limits.network_concurrent_ops)
      .with(DomainResource::Tasks, APPLICATION_TASK_CEILING)
      .with(DomainResource::Control, DOMAIN_CONTROL_CEILING);
    let domain = ResourceDomain::with_waiters(domain_limits, 1, DOMAIN_WAITER_CEILING)
      .map_err(|error| format!("application resource-domain startup failed: {error:?}"))?;
    let fixed_global_control_baseline = domain.snapshot().used.get(DomainResource::Control);
    let tenant = domain
      .tenant(domain_limits)
      .map_err(|error| format!("application tenant startup failed: {error:?}"))?;
    let cpu_gate = CpuGate::new(tenant.clone(), CPU_WAITER_CEILING)
      .map_err(|error| format!("application CPU gate startup failed: {error:?}"))?;
    Ok(Self {
      domain,
      tenant,
      cpu_gate,
      local_limits,
      domain_limits,
      fixed_global_control_baseline,
    })
  }

  pub(crate) fn tenant(&self) -> TenantDomain {
    self.tenant.clone()
  }

  pub(crate) fn local_limits(&self) -> ResourceLimits {
    self.local_limits
  }

  #[cfg(test)]
  pub(crate) fn domain_limits(&self) -> DomainResources {
    self.domain_limits
  }

  pub(crate) fn fixed_global_control_baseline(&self) -> usize {
    self.fixed_global_control_baseline
  }

  pub(crate) fn readback_domain(&self) -> ResourceDomain {
    self.domain.clone()
  }

  pub(crate) fn rate_config(&self) -> ByteRateConfig {
    fixed_rate_config()
  }

  pub(crate) fn for_native(
    &self,
    driver: &MultiThreadDriver,
  ) -> Result<ApplicationRunBindings, String> {
    validate_native_scope_binding(&self.tenant, driver.resources(), self.local_limits)?;
    let io = driver
      .io_bindings()
      .map_err(|error| format!("native I/O bindings failed: {error:?}"))?;
    let disk_rate = driver
      .disk_rate()
      .ok_or_else(|| "native filesystem driver lacks the fixed disk byte bucket".to_owned())?;
    let upload_rate = driver
      .upload_rate()
      .ok_or_else(|| "native runtime lacks the fixed upload byte bucket".to_owned())?;
    let download_rate = driver
      .download_rate()
      .ok_or_else(|| "native runtime lacks the fixed download byte bucket".to_owned())?;
    Ok(ApplicationRunBindings {
      domain: self.domain.clone(),
      tenant: self.tenant.clone(),
      cpu_gate: self.cpu_gate.clone(),
      resources: driver.resources().clone(),
      io: ApplicationIoBindings {
        bindings: io,
        disk_rate,
        upload_rate,
        download_rate,
        blocking_disk_io: None,
      },
      rate_timer_owner: None,
      domain_limits: self.domain_limits,
      fixed_global_control_baseline: self.fixed_global_control_baseline,
    })
  }

  pub(crate) fn for_tokio(&self) -> Result<ApplicationRunBindings, String> {
    let resources = ResourceScope::try_from_tenant(self.local_limits, self.tenant.clone())
      .map_err(|error| format!("Tokio tenant-bound scope startup failed: {error:?}"))?;
    let timer_owner =
      TimerDriver::new_realtime_in_tenant(RATE_TIMER_REGISTRATIONS, &self.tenant)
        .map_err(|error| format!("Tokio fixed-rate timer startup failed: {error:?}"))?;
    let timer = timer_owner.handle();
    let rate = fixed_rate_config();
    let disk_rate = ByteRateLimit::new_in_tenant(rate, &self.tenant)
      .map_err(|error| format!("Tokio disk byte bucket startup failed: {error:?}"))?;
    let upload = ByteRateLimit::new_in_tenant(rate, &self.tenant)
      .map_err(|error| format!("Tokio upload byte bucket startup failed: {error:?}"))?;
    let download = ByteRateLimit::new_in_tenant(rate, &self.tenant)
      .map_err(|error| format!("Tokio download byte bucket startup failed: {error:?}"))?;
    let io = IoBindings::from_components(
      &resources,
      Some(&disk_rate),
      Some(&upload),
      Some(&download),
      Some(&timer),
    )
    .map_err(|error| format!("Tokio I/O bindings failed: {error:?}"))?;
    let blocking_disk_io = (self.local_limits.disk_concurrent_ops != 0)
      .then(|| BlockingByteIo::new(&disk_rate, Some(&self.tenant)))
      .transpose()
      .map_err(|error| format!("Tokio blocking disk byte adapter failed: {error:?}"))?;
    Ok(ApplicationRunBindings {
      domain: self.domain.clone(),
      tenant: self.tenant.clone(),
      cpu_gate: self.cpu_gate.clone(),
      resources: resources.clone(),
      io: ApplicationIoBindings {
        bindings: io,
        disk_rate,
        upload_rate: upload,
        download_rate: download,
        blocking_disk_io,
      },
      rate_timer_owner: Some(timer_owner),
      domain_limits: self.domain_limits,
      fixed_global_control_baseline: self.fixed_global_control_baseline,
    })
  }
}

fn validate_native_scope_binding(
  expected_tenant: &TenantDomain,
  scope: &ResourceScope,
  expected_limits: ResourceLimits,
) -> Result<(), String> {
  if scope.limits() != expected_limits {
    return Err("native runtime resource scope limits differ from the selected domain".into());
  }
  let actual_tenant = scope
    .tenant_domain()
    .ok_or_else(|| "native runtime resource scope is not tenant-bound".to_owned())?;
  if !actual_tenant.same_account(expected_tenant) {
    return Err("native runtime resource scope belongs to a different tenant account".into());
  }
  Ok(())
}

pub(crate) struct ApplicationRunBindings {
  domain: ResourceDomain,
  tenant: TenantDomain,
  cpu_gate: CpuGate,
  resources: ResourceScope,
  io: ApplicationIoBindings,
  rate_timer_owner: Option<TimerDriver>,
  domain_limits: DomainResources,
  fixed_global_control_baseline: usize,
}

impl ApplicationRunBindings {
  pub(crate) fn resources(&self) -> ResourceScope {
    self.resources.clone()
  }

  pub(crate) fn cpu_gate(&self) -> CpuGate {
    self.cpu_gate.clone()
  }

  pub(crate) fn io(&self) -> ApplicationIoBindings {
    self.io.clone()
  }

  pub(crate) fn reserve_task(&self) -> Result<ApplicationTaskLease, String> {
    self.task_admission().reserve()
  }

  pub(crate) fn task_admission(&self) -> ApplicationTaskAdmission {
    ApplicationTaskAdmission {
      tenant: self.tenant.clone(),
    }
  }

  pub(crate) fn snapshots(
    &self,
  ) -> Result<
    (
      allocatbelt::runtime::resource_domain::DomainSnapshot,
      allocatbelt::runtime::resource_domain::DomainSnapshot,
      allocatbelt::runtime::managed::ResourceSnapshot,
    ),
    String,
  > {
    let global = self.domain.snapshot();
    let tenant = self
      .tenant
      .snapshot()
      .map_err(|error| format!("application tenant readback failed: {error:?}"))?;
    Ok((global, tenant, self.resources.snapshot()))
  }

  pub(crate) fn domain_limits(&self) -> DomainResources {
    self.domain_limits
  }

  pub(crate) fn fixed_global_control_baseline(&self) -> usize {
    self.fixed_global_control_baseline
  }

  pub(crate) fn runtime_rows(&self, stage: &str) -> Result<Vec<(String, String)>, String> {
    let (global, tenant, scope) = self.snapshots()?;
    let mut rows = Vec::new();
    let dimensions = [
      ("cpu", DomainResource::Cpu),
      ("memory", DomainResource::Memory),
      ("disk", DomainResource::Disk),
      ("network", DomainResource::Network),
      ("tasks", DomainResource::Tasks),
      ("control", DomainResource::Control),
    ];
    for (owner, snapshot) in [("global", global), ("tenant", tenant)] {
      for (name, resource) in dimensions {
        rows.push((
          format!("{stage}.{owner}.ceiling.{name}"),
          snapshot.ceiling.get(resource).to_string(),
        ));
        rows.push((
          format!("{stage}.{owner}.limit.{name}"),
          snapshot.limit.get(resource).to_string(),
        ));
        rows.push((
          format!("{stage}.{owner}.used.{name}"),
          snapshot.used.get(resource).to_string(),
        ));
      }
      rows.push((
        format!("{stage}.{owner}.live_tenants"),
        snapshot.live_tenants.to_string(),
      ));
    }
    for (name, value) in [
      ("managed_memory_limit", scope.limits.managed_memory),
      ("disk_operation_limit", scope.limits.disk_concurrent_ops),
      (
        "network_operation_limit",
        scope.limits.network_concurrent_ops,
      ),
      ("managed_memory_used", scope.managed_memory),
      ("disk_operations_used", scope.disk_ops),
      ("network_operations_used", scope.network_ops),
    ] {
      rows.push((format!("{stage}.scope.{name}"), value.to_string()));
    }
    rows.extend(
      self
        .io
        .readback_rows()
        .into_iter()
        .map(|(name, value)| (format!("{stage}.io.{name}"), value)),
    );
    Ok(rows)
  }

  pub(crate) fn shutdown_auxiliary_timer(&mut self) -> Result<(), String> {
    if let Some(timer) = self.rate_timer_owner.take() {
      timer
        .shutdown()
        .map_err(|error| format!("Tokio rate timer shutdown failed: {error:?}"))?;
    }
    Ok(())
  }
}

#[must_use = "retain through the lifetime of the task, producer or observer owner"]
pub(crate) struct ApplicationTaskLease(DomainReservation);

impl std::fmt::Debug for ApplicationTaskLease {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ApplicationTaskLease")
      .field("resources", &self.0.resources())
      .finish()
  }
}

#[derive(Clone)]
pub(crate) struct ApplicationTaskAdmission {
  tenant: TenantDomain,
}

impl ApplicationTaskAdmission {
  pub(crate) fn reserve(&self) -> Result<ApplicationTaskLease, String> {
    self
      .tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Tasks, 1))
      .map(ApplicationTaskLease)
      .map_err(|error| format!("application task ceiling refused a role: {error:?}"))
  }
}

#[derive(Clone)]
pub(crate) struct ApplicationIoBindings {
  bindings: IoBindings,
  disk_rate: ByteRateLimit,
  upload_rate: ByteRateLimit,
  download_rate: ByteRateLimit,
  blocking_disk_io: Option<BlockingByteIo>,
}

impl ApplicationIoBindings {
  pub(crate) fn rate_io<T>(&self, endpoint: T) -> Result<RateLimitedIo<T>, String>
  where
    T: AsyncRead + AsyncWrite + Unpin,
  {
    self.bindings.rate_io(endpoint).map_err(|error| {
      format!(
        "application stream rate adapter failed: {:?}",
        error.failure()
      )
    })
  }

  pub(crate) fn blocking_disk_io(&self) -> Option<BlockingByteIo> {
    self.blocking_disk_io.clone()
  }

  #[cfg(test)]
  pub(crate) fn fixed_rate_parameters(&self) -> ByteRateConfig {
    fixed_rate_config()
  }

  pub(crate) fn has_blocking_disk_byte_io(&self) -> bool {
    self.blocking_disk_io.is_some()
  }

  pub(crate) fn readback_rows(&self) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for (direction, bucket) in [
      ("disk", &self.disk_rate),
      ("upload", &self.upload_rate),
      ("download", &self.download_rate),
    ] {
      let snapshot = bucket.snapshot();
      rows.push((
        format!("{direction}_bytes_per_second"),
        snapshot.bytes_per_second.to_string(),
      ));
      rows.push((
        format!("{direction}_burst_bytes"),
        snapshot.burst_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_ceiling_bytes_per_second"),
        snapshot.ceiling_bytes_per_second.to_string(),
      ));
      rows.push((
        format!("{direction}_ceiling_burst_bytes"),
        snapshot.ceiling_burst_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_max_reservations"),
        snapshot.max_reservations.to_string(),
      ));
      rows.push((
        format!("{direction}_available_bytes"),
        snapshot.available_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_reserved_bytes"),
        snapshot.reserved_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_reservations"),
        snapshot.reservations.to_string(),
      ));
    }
    rows
  }
}

#[cfg(test)]
#[path = "runtime_bindings_tests.rs"]
mod tests;
