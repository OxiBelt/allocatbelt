//! Separate construction-only evidence for the frozen application domain.
//!
//! Run this from the same immutable target build as the application binaries.
//! The controller must pin this artifact and its output before any pair runs;
//! a treatment's echoed baseline is never calibration evidence.

use allocatbelt::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

fn main() -> std::process::ExitCode {
  match calibrate() {
    Ok(()) => std::process::ExitCode::SUCCESS,
    Err(message) => {
      eprintln!("resource-domain calibration failed: {message}");
      std::process::ExitCode::FAILURE
    }
  }
}

fn calibrate() -> Result<(), String> {
  const TENANTS: usize = 1;
  const WAITERS: usize = 256;
  const CONTROL_CEILING: usize = 64 * 1024 * 1024;
  let limits = DomainResources::ZERO.with(DomainResource::Control, CONTROL_CEILING);
  let domain = ResourceDomain::with_waiters(limits, TENANTS, WAITERS)
    .map_err(|error| format!("construction: {error:?}"))?;
  let initial = domain.snapshot();
  if initial.live_tenants != 0 || initial.ceiling != limits || initial.limit != limits {
    return Err("unexpected empty-domain configuration".into());
  }
  let baseline = initial.used.get(DomainResource::Control);
  if baseline == 0 || baseline > CONTROL_CEILING {
    return Err("invalid baseline Control charge".into());
  }
  let tenant = domain
    .tenant(limits)
    .map_err(|error| format!("tenant construction: {error:?}"))?;
  let occupied = domain.snapshot();
  if occupied.live_tenants != TENANTS || occupied.used.get(DomainResource::Control) < baseline {
    return Err("unexpected tenant accounting".into());
  }
  let tenant_owner_bytes = occupied.used.get(DomainResource::Control) - baseline;
  drop(tenant);
  let final_state = domain.snapshot();
  if final_state.live_tenants != 0 || final_state.used != initial.used {
    return Err("construction-only calibration did not release its tenant".into());
  }
  println!(
    "{{\"schema\":\"allocatbelt.resource-domain-calibration.v1\",\"architecture\":\"{}\",\"max_tenants\":{TENANTS},\"max_waiters\":{WAITERS},\"control_ceiling\":{CONTROL_CEILING},\"fixed_global_control_baseline\":{baseline},\"tenant_owner_control_bytes\":{tenant_owner_bytes},\"final_live_tenants\":0,\"final_global_control_bytes\":{baseline}}}",
    std::env::consts::ARCH
  );
  Ok(())
}
