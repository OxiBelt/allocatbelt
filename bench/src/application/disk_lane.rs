//! Bounded positional-file comparison adapter.
//!
//! Both variants use the application-port workspace, payload generator,
//! configured offset and checksum. Native filesystem operations use
//! `FsHandle`; Tokio uses four bounded `spawn_blocking` workers and the same
//! filesystem-operation ledger around each equivalent transaction stage.

use std::collections::HashSet;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::thread::{self, ThreadId};
use std::time::Duration;

use allocatbelt::runtime::fs::FsHandle;
use allocatbelt::runtime::managed::{OperationRequest, ResourceScope};
use allocatbelt_app_ports::disk::{self, DiskConfig, DiskReport};
use allocatbelt_app_ports::memory;

use super::Options;

pub(crate) fn warm_native_workers(
  runtime: &allocatbelt::runtime::Runtime,
  async_handle: &allocatbelt::runtime::asynchronous::AsyncHandle,
  workers: usize,
) -> Result<(), String> {
  let gate = super::WarmGate::new(workers, Duration::from_secs(30));
  let mut jobs = Vec::new();
  jobs
    .try_reserve_exact(workers)
    .map_err(|_| "could not reserve native disk worker warm-up handles".to_owned())?;
  for _ in 0..workers {
    let gate = Arc::clone(&gate);
    jobs.push(
      runtime
        .handle()
        .try_spawn(allocatbelt::runtime::Resources::ZERO, move |_token| {
          let thread_id = thread::current().id();
          let released = gate.arrive_and_wait();
          (thread_id, released)
        })
        .map_err(|error| format!("native disk worker warm-up admission failed: {error:?}"))?,
    );
  }
  gate.release_after_all(workers)?;
  let mut seen = HashSet::<ThreadId>::new();
  for job in jobs {
    let (thread_id, released) = async_handle
      .block_on(job)
      .map_err(|error| format!("native disk warm-up root failed: {error}"))?
      .map_err(|error| format!("native disk warm-up task failed: {error}"))?;
    if !released {
      return Err("native disk worker warm-up gate timed out".into());
    }
    seen.insert(thread_id);
  }
  if seen.len() != workers {
    return Err(format!(
      "expected {workers} native filesystem workers, saw {}",
      seen.len()
    ));
  }
  Ok(())
}

pub(crate) fn warm_tokio_workers(
  handle: &tokio::runtime::Handle,
  workers: usize,
) -> Result<(), String> {
  let gate = super::WarmGate::new(workers, Duration::from_secs(30));
  let mut jobs = Vec::new();
  jobs
    .try_reserve_exact(workers)
    .map_err(|_| "could not reserve Tokio disk worker warm-up handles".to_owned())?;
  for _ in 0..workers {
    let gate = Arc::clone(&gate);
    jobs.push(handle.spawn_blocking(move || {
      let thread_id = thread::current().id();
      let released = gate.arrive_and_wait();
      (thread_id, released)
    }));
  }
  gate.release_after_all(workers)?;
  let mut seen = HashSet::<ThreadId>::new();
  for job in jobs {
    let (thread_id, released) = handle
      .block_on(job)
      .map_err(|error| format!("Tokio disk worker warm-up failed: {error}"))?;
    if !released {
      return Err("Tokio disk worker warm-up gate timed out".into());
    }
    seen.insert(thread_id);
  }
  if seen.len() != workers {
    return Err(format!(
      "expected {workers} Tokio blocking workers, saw {}",
      seen.len()
    ));
  }
  Ok(())
}

pub(crate) async fn run_native_operation(
  fs_handle: &FsHandle,
  resources: &ResourceScope,
  config: DiskConfig,
) -> allocatbelt_app_ports::PortResult<DiskReport> {
  disk::run_operation(fs_handle, resources, config).await
}

pub(crate) async fn run_tokio_operation(
  handle: &tokio::runtime::Handle,
  slots: &Arc<tokio::sync::Semaphore>,
  resources: &ResourceScope,
  config: DiskConfig,
) -> Result<DiskReport, String> {
  let mut workspace = disk::DiskWorkspace::create()
    .map_err(|error| format!("disk workspace setup failed: {error}"))?;
  let open_path = workspace.file_path().to_path_buf();
  let mut file = submit_step(handle, slots, resources, move || {
    disk::existing_payload_options().open(open_path)
  })
  .await?;

  let payload = disk::make_payload(resources, config).map_err(|error| error.to_string())?;
  let expected_checksum = memory::checksum(payload.as_slice());
  let (next_file, payload, written) = submit_step(handle, slots, resources, move || {
    let mut written = 0usize;
    let bytes = payload.as_slice();
    while written < bytes.len() {
      let end = written
        .saturating_add(disk::IO_CHUNK_BYTES)
        .min(bytes.len());
      let position = config
        .offset
        .checked_add(written as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk write offset overflow"))?;
      match file.write_at(&bytes[written..end], position) {
        Ok(0) => {
          return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "positional write made no progress",
          ));
        }
        Ok(count) => written += count,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(error),
      }
    }
    Ok((file, payload, written))
  })
  .await?;
  file = next_file;
  if written != config.bytes {
    return Err(format!("short positional write: {written} bytes"));
  }
  drop(payload);

  file = submit_step(handle, slots, resources, move || {
    file.flush()?;
    Ok(file)
  })
  .await?;
  file = submit_step(handle, slots, resources, move || {
    file.sync_all()?;
    Ok(file)
  })
  .await?;

  let mut readback = resources
    .try_alloc_zeroed(config.bytes)
    .map_err(|error| error.to_string())?;
  let (next_file, readback, read) = submit_step(handle, slots, resources, move || {
    let Some(bytes) = readback.get_mut() else {
      return Err(io::Error::other("new disk readback buffer is shared"));
    };
    let mut read = 0usize;
    while read < bytes.len() {
      let end = read.saturating_add(disk::IO_CHUNK_BYTES).min(bytes.len());
      let position = config
        .offset
        .checked_add(read as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk read offset overflow"))?;
      match file.read_at(&mut bytes[read..end], position) {
        Ok(0) => break,
        Ok(count) => read += count,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(error),
      }
    }
    Ok((file, readback, read))
  })
  .await?;
  file = next_file;
  if read != config.bytes {
    return Err(format!("short positional read: {read} bytes"));
  }
  let actual_checksum = allocatbelt_app_ports::memory::checksum(readback.as_slice());
  if actual_checksum != expected_checksum {
    return Err("disk readback checksum mismatch".into());
  }
  drop(readback);
  drop(file);
  let resources_after_cleanup = resources.snapshot();
  workspace
    .cleanup()
    .map_err(|error| format!("disk workspace cleanup failed: {error}"))?;
  let temp_directory_removed = !workspace.file_path().exists();
  if !temp_directory_removed {
    return Err("disk workspace remained after cleanup".into());
  }
  Ok(DiskReport {
    offset: config.offset,
    bytes: config.bytes,
    checksum: actual_checksum,
    resources_after_cleanup,
    temp_directory_removed,
  })
}

async fn submit_step<T>(
  handle: &tokio::runtime::Handle,
  slots: &Arc<tokio::sync::Semaphore>,
  resources: &ResourceScope,
  operation: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, String>
where
  T: Send + 'static,
{
  let slot = slots
    .clone()
    .acquire_owned()
    .await
    .map_err(|error| format!("Tokio disk step window closed: {error}"))?;
  let ledger = resources
    .try_acquire(OperationRequest {
      disk: 1,
      network: 0,
    })
    .map_err(|error| format!("Tokio disk operation admission failed: {error}"))?;
  handle
    .spawn_blocking(move || {
      let _slot = slot;
      let _ledger = ledger;
      operation()
    })
    .await
    .map_err(|error| format!("Tokio blocking filesystem job failed: {error}"))?
    .map_err(|error| format!("Tokio filesystem operation failed: {error}"))
}

pub(crate) fn run_and_print(allocator: &str, options: Options) -> Result<(), String> {
  if options.workload != super::Workload::Disk {
    return Err("disk lane received a non-disk workload".into());
  }
  let counts = super::run(options)?;
  super::print_row(allocator, options, &counts);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::run_tokio_operation;
  use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
  use allocatbelt_app_ports::disk::DiskConfig;
  use std::sync::Arc;

  #[test]
  fn tokio_multi_chunk_positional_transaction_reads_back_and_cleans() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .max_blocking_threads(2)
      .enable_all()
      .build()
      .unwrap();
    let resources = ResourceScope::new(ResourceLimits {
      managed_memory: 1024 * 1024,
      disk_concurrent_ops: 2,
      network_concurrent_ops: 0,
    });
    let slots = Arc::new(tokio::sync::Semaphore::new(2));
    let config = DiskConfig {
      bytes: 2 * 64 * 1024 + 31,
      offset: 4093,
      seed: 0x1234_5678,
    };
    let report = runtime
      .block_on(run_tokio_operation(
        runtime.handle(),
        &slots,
        &resources,
        config,
      ))
      .expect("Tokio disk transaction should verify");
    assert_eq!(report.offset, config.offset);
    assert_eq!(report.bytes, config.bytes);
    assert!(report.temp_directory_removed);
    assert_eq!(resources.snapshot().managed_memory, 0);
    assert_eq!(resources.snapshot().disk_ops, 0);
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
  }
}
