//! Managed-buffer workload and deterministic byte kernels.

use allocatbelt::runtime::asynchronous::{AsyncJoinError, OwnedTaskScope};
use allocatbelt::runtime::managed::{
  ManagedBuf, ResourceError, ResourceKind, ResourceLimits, ResourceScope,
};

use crate::{PortResult, join_message, message};

/// Maximum buffer size used by the functional example.
pub const MAX_BUFFER_BYTES: usize = 1 << 20;

/// Bounded input to [`run`]. The growth target must be larger than the
/// initial allocation so the replacement reservation includes both buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryConfig {
  /// Initial managed storage in bytes.
  pub initial_bytes: usize,
  /// Replacement length in bytes.
  pub grown_bytes: usize,
  /// Seed for deterministic bytes.
  pub seed: u64,
}

impl Default for MemoryConfig {
  fn default() -> Self {
    Self {
      initial_bytes: 4096,
      grown_bytes: 8192,
      seed: 0x243f_6a88_85a3_08d3,
    }
  }
}

/// Charges observed after successful replacement and its payload checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryReport {
  /// The old plus replacement reservation was refused under the exact cap.
  pub peak_replacement_was_enforced: bool,
  /// Managed bytes charged after the old buffer was replaced.
  pub charged_after_growth: usize,
  /// Checksum over the initialized grown payload.
  pub checksum: u64,
}

/// A deterministic byte shared by allocator and executor adapters.
#[must_use]
pub fn pattern_byte(seed: u64, index: usize) -> u8 {
  let mut value = seed ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
  value ^= value >> 30;
  value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
  value ^= value >> 27;
  value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
  (value ^ (value >> 31)) as u8
}

/// FNV-1a checksum used by every application lane's readback validation.
#[must_use]
pub fn checksum(bytes: &[u8]) -> u64 {
  bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
  })
}

fn fill(buf: &mut ManagedBuf, seed: u64) -> PortResult<()> {
  let Some(bytes) = buf.get_mut() else {
    return Err(message("managed buffer unexpectedly has shared owners").into());
  };
  for (index, byte) in bytes.iter_mut().enumerate() {
    *byte = pattern_byte(seed, index);
  }
  Ok(())
}

fn managed_work(resources: &ResourceScope, config: MemoryConfig) -> PortResult<MemoryReport> {
  if config.initial_bytes == 0
    || config.grown_bytes <= config.initial_bytes
    || config.grown_bytes > MAX_BUFFER_BYTES
  {
    return Err(message("memory config exceeds its functional bounds").into());
  }

  // This smaller scope proves that a move to a replacement needs the old and
  // new storage together. The requested target alone fits, but old+target
  // cannot fit. `try_resize` must preserve the old bytes and charge on reject.
  let peak_limit = config
    .initial_bytes
    .checked_add(config.grown_bytes)
    .and_then(|sum| sum.checked_sub(1))
    .ok_or_else(|| message("memory peak limit overflow"))?;
  let peak_scope = ResourceScope::new(ResourceLimits {
    managed_memory: peak_limit,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let mut probe = peak_scope.try_alloc_zeroed(config.initial_bytes)?;
  fill(&mut probe, config.seed)?;
  let probe_charge = probe.charged_bytes();
  if config.grown_bytes <= probe_charge {
    return Err(message("growth target did not exceed retained initial capacity").into());
  }
  let prefix_checksum = checksum(probe.as_slice());
  let refused = matches!(
    probe.try_resize(config.grown_bytes),
    Err(ResourceError::Exhausted(ResourceKind::Memory))
  );
  if !refused
    || probe.len() != config.initial_bytes
    || probe.charged_bytes() != probe_charge
    || checksum(probe.as_slice()) != prefix_checksum
    || peak_scope.snapshot().managed_memory != probe_charge
  {
    return Err(message("managed replacement did not preserve its exact-peak contract").into());
  }
  drop(probe);
  if peak_scope.snapshot().managed_memory != 0 {
    return Err(message("peak-probe buffer charge was not released").into());
  }

  let mut buffer = resources.try_alloc_zeroed(config.initial_bytes)?;
  fill(&mut buffer, config.seed)?;
  let old_prefix = checksum(buffer.as_slice());
  buffer.try_resize(config.grown_bytes)?;
  if checksum(&buffer.as_slice()[..config.initial_bytes]) != old_prefix
    || buffer.as_slice()[config.initial_bytes..]
      .iter()
      .any(|&byte| byte != 0)
  {
    return Err(message("managed growth did not preserve and zero-fill bytes").into());
  }
  if let Some(bytes) = buffer.get_mut() {
    for (index, byte) in bytes[config.initial_bytes..].iter_mut().enumerate() {
      *byte = pattern_byte(config.seed, config.initial_bytes + index);
    }
  } else {
    return Err(message("grown buffer unexpectedly has shared owners").into());
  }
  let charged_after_growth = resources.snapshot().managed_memory;
  if charged_after_growth != buffer.charged_bytes() {
    return Err(message("ledger does not match retained grown storage").into());
  }
  let report = MemoryReport {
    peak_replacement_was_enforced: true,
    charged_after_growth,
    checksum: checksum(buffer.as_slice()),
  };
  drop(buffer);
  if resources.snapshot().managed_memory != 0 {
    return Err(message("grown managed buffer charge was not released").into());
  }
  Ok(report)
}

/// Runs the managed allocation, replacement-growth, byte-validation and
/// cleanup path inside a bounded owned task scope.
pub async fn run(
  scope: &OwnedTaskScope,
  resources: ResourceScope,
  config: MemoryConfig,
) -> PortResult<MemoryReport> {
  let job = scope
    .spawn(async move { managed_work(&resources, config) })
    .map_err(|error| join_message(error.kind))?;
  job
    .await
    .map_err(|error: AsyncJoinError| join_message(error))?
}

#[cfg(test)]
mod tests {
  use super::{MemoryConfig, checksum, pattern_byte};

  #[test]
  fn deterministic_payload_changes_with_seed_and_position() {
    let bytes_a: Vec<u8> = (0..128).map(|index| pattern_byte(5, index)).collect();
    let bytes_b: Vec<u8> = (0..128).map(|index| pattern_byte(6, index)).collect();
    assert_ne!(bytes_a, bytes_b);
    assert_ne!(bytes_a[2], bytes_a[3]);
    assert_eq!(checksum(b"abc"), 0xe71f_a219_0541_574b);
    assert_ne!(
      MemoryConfig::default().initial_bytes,
      MemoryConfig::default().grown_bytes
    );
  }
}
