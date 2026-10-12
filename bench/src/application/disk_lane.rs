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
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, ThreadId};
use std::time::Duration;

use allocatbelt::runtime::Handle as BlockingHandle;
use allocatbelt::runtime::cpu_gate::CpuGate;
use allocatbelt::runtime::fs::BlockingByteIo;
use allocatbelt::runtime::fs::FsHandle;
use allocatbelt::runtime::managed::{OperationRequest, ResourceScope};
use allocatbelt_app_ports::disk::{self, DiskConfig, DiskReport};
use allocatbelt_app_ports::memory;

use super::{ApplicationTaskAdmission, Options};

pub(crate) fn warm_native_workers(
  runtime: &BlockingHandle,
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
      .map_err(|error| format!("native disk warm-up job failed: {error}"))?;
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
  disk_io: &BlockingByteIo,
  cpu_gate: &CpuGate,
  task_admission: &ApplicationTaskAdmission,
  config: DiskConfig,
) -> Result<DiskReport, String> {
  let mut workspace = disk::DiskWorkspace::create()
    .map_err(|error| format!("disk workspace setup failed: {error}"))?;
  let open_path = workspace.file_path().to_path_buf();
  let mut file = submit_step(
    handle,
    slots,
    resources,
    cpu_gate,
    task_admission,
    move |_| disk::existing_payload_options().open(open_path),
  )
  .await?;

  let payload = disk::make_payload(resources, config).map_err(|error| error.to_string())?;
  let expected_checksum = memory::checksum(payload.as_slice());
  let write_rate = disk_io.clone();
  let (next_file, payload, written) = submit_step(
    handle,
    slots,
    resources,
    cpu_gate,
    task_admission,
    move |cancelled| {
      let written = write_all_at(
        &mut file,
        payload.as_slice(),
        config.offset,
        &write_rate,
        cancelled,
      )?;
      Ok((file, payload, written))
    },
  )
  .await?;
  file = next_file;
  if written != config.bytes {
    return Err(format!("short positional write: {written} bytes"));
  }
  drop(payload);

  file = submit_step(
    handle,
    slots,
    resources,
    cpu_gate,
    task_admission,
    move |_| {
      file.flush()?;
      Ok(file)
    },
  )
  .await?;
  file = submit_step(
    handle,
    slots,
    resources,
    cpu_gate,
    task_admission,
    move |_| {
      file.sync_all()?;
      Ok(file)
    },
  )
  .await?;

  let mut readback = resources
    .try_alloc_zeroed(config.bytes)
    .map_err(|error| error.to_string())?;
  let read_rate = disk_io.clone();
  let (next_file, readback, read) = submit_step(
    handle,
    slots,
    resources,
    cpu_gate,
    task_admission,
    move |cancelled| {
      let Some(bytes) = readback.get_mut() else {
        return Err(io::Error::other("new disk readback buffer is shared"));
      };
      let read = read_at(&mut file, bytes, config.offset, &read_rate, cancelled)?;
      Ok((file, readback, read))
    },
  )
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
  cpu_gate: &CpuGate,
  task_admission: &ApplicationTaskAdmission,
  operation: impl FnOnce(&AtomicBool) -> io::Result<T> + Send + 'static,
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
  let task_lease = task_admission.reserve()?;
  let cancellation = Arc::new(AtomicBool::new(false));
  let cancellation_for_worker = Arc::clone(&cancellation);
  let cancellation_guard = CancellationGuard(cancellation);
  let cpu_gate = cpu_gate.clone();
  let result = handle
    .spawn_blocking(move || {
      let _slot = slot;
      let _ledger = ledger;
      let _task_lease = task_lease;
      cpu_gate
        .run(|| {
          if cancellation_for_worker.load(Ordering::Acquire) {
            return Err(io::Error::new(
              io::ErrorKind::Interrupted,
              "Tokio disk step cancelled before I/O",
            ));
          }
          operation(&cancellation_for_worker)
        })
        .map_err(|error| {
          io::Error::other(format!("Tokio disk CPU admission failed: {:?}", error.kind))
        })?
    })
    .await
    .map_err(|error| format!("Tokio blocking filesystem job failed: {error}"))?
    .map_err(|error| format!("Tokio filesystem operation failed: {error}"));
  drop(cancellation_guard);
  result
}

struct CancellationGuard(Arc<AtomicBool>);

impl Drop for CancellationGuard {
  fn drop(&mut self) {
    self.0.store(true, Ordering::Release);
  }
}

fn write_all_at(
  file: &mut std::fs::File,
  bytes: &[u8],
  offset: u64,
  disk_io: &BlockingByteIo,
  cancelled: &AtomicBool,
) -> io::Result<usize> {
  let mut written = 0usize;
  while written < bytes.len() {
    let maximum = disk::IO_CHUNK_BYTES.min(bytes.len() - written);
    let position = offset
      .checked_add(written as u64)
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk write offset overflow"))?;
    match disk_io.run(
      maximum,
      || cancelled.load(Ordering::Acquire),
      |offered| file.write_at(&bytes[written..written + offered], position),
    ) {
      Ok(0) => {
        return Err(io::Error::new(
          io::ErrorKind::WriteZero,
          "positional write made no progress",
        ));
      }
      Ok(count) => written += count,
      Err(error)
        if error.kind() == io::ErrorKind::Interrupted && !cancelled.load(Ordering::Acquire) => {}
      Err(error) => return Err(error),
    }
  }
  Ok(written)
}

fn read_at(
  file: &mut std::fs::File,
  bytes: &mut [u8],
  offset: u64,
  disk_io: &BlockingByteIo,
  cancelled: &AtomicBool,
) -> io::Result<usize> {
  let mut read = 0usize;
  while read < bytes.len() {
    let maximum = disk::IO_CHUNK_BYTES.min(bytes.len() - read);
    let position = offset
      .checked_add(read as u64)
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk read offset overflow"))?;
    match disk_io.run(
      maximum,
      || cancelled.load(Ordering::Acquire),
      |offered| file.read_at(&mut bytes[read..read + offered], position),
    ) {
      Ok(0) => break,
      Ok(count) => read += count,
      Err(error)
        if error.kind() == io::ErrorKind::Interrupted && !cancelled.load(Ordering::Acquire) => {}
      Err(error) => return Err(error),
    }
  }
  Ok(read)
}

pub(crate) fn run_and_print(
  allocator: &str,
  options: Options,
  plan: super::ArrivalPlan,
) -> Result<(), String> {
  if options.workload != super::Workload::Disk {
    return Err("disk lane received a non-disk workload".into());
  }
  let counts = super::run_with_plan(options, plan, None)?;
  super::write_id_report(&counts.observer.records, allocator, options, plan.profile)?;
  super::print_row(allocator, options, &counts);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::{run_tokio_operation, submit_step};
  use crate::application::{ApplicationDomain, Workload};
  use allocatbelt_app_ports::disk::DiskConfig;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Condvar, Mutex};
  use std::thread;
  use std::time::{Duration, Instant};

  #[test]
  fn tokio_multi_chunk_positional_transaction_reads_back_and_cleans() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .max_blocking_threads(2)
      .enable_all()
      .build()
      .unwrap();
    let domain = ApplicationDomain::new(Workload::Disk, 2).expect("disk domain");
    let mut bindings = domain.for_tokio().expect("Tokio bindings");
    let resources = bindings.resources();
    let io = bindings.io();
    let disk_io = io.blocking_disk_io().expect("disk byte adapter");
    let cpu_gate = bindings.cpu_gate();
    let task_admission = bindings.task_admission();
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
        &disk_io,
        &cpu_gate,
        &task_admission,
        config,
      ))
      .expect("Tokio disk transaction should verify");
    assert_eq!(report.offset, config.offset);
    assert_eq!(report.bytes, config.bytes);
    assert!(report.temp_directory_removed);
    assert_eq!(resources.snapshot().managed_memory, 0);
    assert_eq!(resources.snapshot().disk_ops, 0);
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    bindings
      .shutdown_auxiliary_timer()
      .expect("rate timer shutdown");
  }

  #[test]
  fn tokio_filesystem_semaphore_caps_more_jobs_than_workers_until_completion() {
    const WORKERS: usize = 2;
    const JOBS: usize = 7;
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .max_blocking_threads(WORKERS + 1)
      .enable_all()
      .build()
      .unwrap();
    let domain = ApplicationDomain::new(Workload::Disk, 2).expect("disk domain");
    let mut bindings = domain.for_tokio().expect("Tokio bindings");
    let resources = bindings.resources();
    let cpu_gate = bindings.cpu_gate();
    let task_admission = bindings.task_admission();
    let slots = Arc::new(tokio::sync::Semaphore::new(WORKERS));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let jobs = (0..JOBS)
      .map(|_| {
        let handle = runtime.handle().clone();
        let task_handle = handle.clone();
        let slots = Arc::clone(&slots);
        let resources = resources.clone();
        let cpu_gate = cpu_gate.clone();
        let task_admission = task_admission.clone();
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let released = Arc::clone(&released);
        handle.spawn(async move {
          let operation_handle = task_handle.clone();
          submit_step(
            &operation_handle,
            &slots,
            &resources,
            &cpu_gate,
            &task_admission,
            move |_cancelled| {
              let current = active.fetch_add(1, Ordering::SeqCst) + 1;
              peak.fetch_max(current, Ordering::SeqCst);
              let (lock, changed) = &*released;
              let mut is_released = lock.lock().unwrap_or_else(|error| error.into_inner());
              while !*is_released {
                is_released = changed
                  .wait(is_released)
                  .unwrap_or_else(|error| error.into_inner());
              }
              active.fetch_sub(1, Ordering::SeqCst);
              Ok(())
            },
          )
          .await
        })
      })
      .collect::<Vec<_>>();

    let deadline = Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::SeqCst) < WORKERS && Instant::now() < deadline {
      thread::sleep(Duration::from_millis(1));
    }
    let reached_limit = active.load(Ordering::SeqCst) == WORKERS;
    {
      let (lock, changed) = &*released;
      *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
      changed.notify_all();
    }
    for job in jobs {
      runtime
        .block_on(job)
        .expect("Tokio filesystem wrapper task should join")
        .expect("Tokio filesystem step should complete");
    }
    assert!(
      reached_limit,
      "filesystem workers did not fill the configured cap"
    );
    assert_eq!(peak.load(Ordering::SeqCst), WORKERS);
    assert_eq!(resources.snapshot().disk_ops, 0);
    runtime.shutdown_timeout(Duration::from_secs(5));
    bindings
      .shutdown_auxiliary_timer()
      .expect("rate timer shutdown");
  }
}
