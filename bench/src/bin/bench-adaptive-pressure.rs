//! Bounded caller-driven measured feedback for an externally supplied cgroup.
//!
//! Usage: `bench-adaptive-pressure --group-dir LEAF_PATH < supervisor-event-stream.tsv`
//! An external supervisor owns workload placement and writes actual work events
//! to stdin. This binary does not create synthetic work or discover/move cgroups.

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use allocatbelt::runtime::adaptive::{
  AdaptiveConfig, AdaptiveController, AdaptiveThresholds, AdaptiveTier,
};
use allocatbelt::runtime::cgroup::{CgroupCeilings, CgroupV2, CpuMax, Limit};
use allocatbelt_bench::adaptive_feedback::{
  Conservation, Disposition, FeedbackUnavailable, SafetyCounters, SensorError, SensorReader,
  SensorSnapshot, WindowFeedback, WindowLedger, feedback_for_window,
};
use rustix::fd::OwnedFd;

const PERIOD_US: u64 = 100_000;
const MEMORY_MAX: u64 = 512 * 1024 * 1024;
const MEMORY_HIGH: [u64; 3] = [64 * 1024 * 1024, 128 * 1024 * 1024, 192 * 1024 * 1024];
const QUOTAS_US: [u64; 3] = [50_000, 100_000, 150_000];
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const MAX_WINDOWS: usize = 1024;
const MAX_IDS: usize = 16_384;
const MAX_DRAIN: Duration = Duration::from_secs(10);
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_EVENT_DELAY_NS: u64 = 250_000_000;
const MAX_OBSERVE_RELEASE_DELAY: Duration = Duration::from_millis(250);

struct CappedOutput<W> {
  inner: W,
  written: usize,
}

impl<W: Write> Write for CappedOutput<W> {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    let next = self
      .written
      .checked_add(bytes.len())
      .ok_or_else(|| io::Error::other("output byte count overflow"))?;
    if next > MAX_OUTPUT_BYTES {
      return Err(io::Error::new(
        io::ErrorKind::WriteZero,
        "feedback output cap exceeded",
      ));
    }
    self.inner.write_all(bytes)?;
    self.written = next;
    Ok(bytes.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    self.inner.flush()
  }
}

struct WindowStart {
  index: u32,
  phase: String,
  controls: allocatbelt::runtime::cgroup::CgroupSnapshot,
  sensors: SensorSnapshot,
  controls_started: Instant,
  controls_finished: Instant,
}

struct WindowEvidence<'a> {
  window: &'a WindowStart,
  end_controls_started: Instant,
  end_controls_finished: Instant,
  end: &'a SensorSnapshot,
  end_controls: &'a allocatbelt::runtime::cgroup::CgroupSnapshot,
  counts: &'a Conservation,
}

fn run() -> Result<(), String> {
  let mut args = std::env::args().skip(1);
  if args.next().as_deref() != Some("--group-dir") {
    return Err("usage: bench-adaptive-pressure --group-dir LEAF_PATH < event-stream.tsv".into());
  }
  let group_path = args.next().ok_or("missing --group-dir path")?;
  if args.next().is_some() {
    return Err("unexpected arguments".into());
  }
  let group_file =
    File::open(&group_path).map_err(|error| format!("open supplied cgroup leaf: {error}"))?;
  let sensor_fd: OwnedFd = group_file
    .try_clone()
    .map_err(|error| format!("duplicate supplied group descriptor: {error}"))?
    .into();
  let control_fd: OwnedFd = group_file.into();
  let sensor =
    SensorReader::new(sensor_fd).map_err(|error| format!("sensor descriptor: {error:?}"))?;

  let quota_ceiling = cpu_max(QUOTAS_US[2])?;
  let ceilings = CgroupCeilings::new(quota_ceiling, MEMORY_HIGH[2], MEMORY_MAX);
  let cgroup = CgroupV2::open(control_fd, ceilings)
    .map_err(|error| format!("supplied cgroup capability: {error:?}"))?;
  let tiers = [
    AdaptiveTier {
      cpu_max: cpu_max(QUOTAS_US[0])?,
      memory_high_bytes: MEMORY_HIGH[0],
    },
    AdaptiveTier {
      cpu_max: cpu_max(QUOTAS_US[1])?,
      memory_high_bytes: MEMORY_HIGH[1],
    },
    AdaptiveTier {
      cpu_max: cpu_max(QUOTAS_US[2])?,
      memory_high_bytes: MEMORY_HIGH[2],
    },
  ];
  let thresholds = AdaptiveThresholds::new(
    Duration::from_millis(5),
    Duration::from_millis(20),
    2_000,
    8_000,
    2_000,
    5_000,
  )
  .map_err(|error| format!("adaptive thresholds: {error}"))?;
  let policy = AdaptiveConfig::new(
    thresholds,
    3,
    3,
    Duration::from_millis(250),
    Duration::from_secs(2),
    Duration::from_secs(1),
  )
  .map_err(|error| format!("adaptive policy: {error}"))?;
  let mut controller = AdaptiveController::new(cgroup, &tiers, policy)
    .map_err(|error| format!("adaptive controller startup: {error:?}"))?;
  let stdout = io::stdout();
  let mut output = CappedOutput {
    inner: stdout.lock(),
    written: 0,
  };
  let original_controls_started = Instant::now();
  let original = match controller.readback() {
    Ok(snapshot) => snapshot,
    Err(error) => {
      let failed_at = Instant::now();
      writeln!(output, "initial_control_readback_error\tstarted_at={original_controls_started:?} failed_at={failed_at:?} error={error:?}")
        .and_then(|()| output.flush())
        .map_err(|write_error| format!("write initial control error: {write_error}"))?;
      return Err(format!("initial control readback: {error}"));
    }
  };
  let original_controls_finished = Instant::now();
  writeln!(output, "initial_control_boundary\tcontrols={original_controls_started:?}..{original_controls_finished:?} control_snapshot={original:?}")
    .map_err(|error| format!("write initial control boundary: {error}"))?;
  output
    .flush()
    .map_err(|error| format!("flush initial control boundary: {error}"))?;
  if original.memory_max != Limit::Value(MEMORY_MAX) {
    writeln!(
      output,
      "initial_safety_failed\treason=OriginalMemoryMax observed={:?} expected={MEMORY_MAX}",
      original.memory_max
    )
    .and_then(|()| output.flush())
    .map_err(|error| format!("write initial memory maximum failure: {error}"))?;
    return Err("initial memory.max does not equal the fixed 512 MiB denominator".into());
  }
  let mut ledger =
    WindowLedger::new(MAX_IDS).map_err(|error| format!("window ledger: {error:?}"))?;
  let stdin = io::stdin();
  let mut input = stdin.lock();
  let initial_sensors = match sensor.read() {
    Ok(snapshot) => snapshot,
    Err(error) => {
      print_sensor_error(&mut output, "initial_sensors", &error)?;
      return Err(format!("initial sensors: {error:?}"));
    }
  };
  let mut safety = SafetyCounters::from_snapshot(&initial_sensors);
  if let Err(reason) = safety.check_next(&initial_sensors, MEMORY_MAX) {
    print_boundary(
      &mut output,
      "initial_safety_failure",
      0,
      &initial_sensors,
      &original,
    )?;
    return Err(format!(
      "initial invocation safety baseline failed: {reason:?}"
    ));
  }
  writeln!(output, "initial_boundary\tcontrols={original_controls_started:?}..{original_controls_finished:?} control_snapshot={original:?} sensor={initial_sensors:?}")
    .map_err(|error| format!("write initial boundary: {error}"))?;
  print_raw_sensors(&mut output, 0, "initial", &initial_sensors)?;
  writeln!(output, "READY_FOR_WINDOW\ttier={}", controller.tier_index())
    .and_then(|()| output.flush())
    .map_err(|error| format!("ready output: {error}"))?;
  let mut total_bytes = 0usize;
  let mut window_count = 0usize;
  let mut active: Option<WindowStart> = None;
  let mut drain_started: Option<(Instant, Duration)> = None;
  let mut drain_complete = false;
  let mut seen_phases = [false; 8];
  let mut last_phase = None;
  let mut last_real_sample = None;
  let mut line = Vec::with_capacity(256);

  let result = (|| -> Result<(), String> {
    loop {
      let has_row = match read_row(&mut input, &mut line, &mut total_bytes) {
        Ok(has_row) => has_row,
        Err(error) => {
          let _ = writeln!(
            output,
            "input_read_error\terror={error:?} raw_prefix={line:?}"
          );
          return Err(error);
        }
      };
      if !has_row {
        break;
      }
      let received_at = Instant::now();
      let received_at_ns = monotonic_now_ns()?;
      writeln!(
        output,
        "input_row\tbytes={line:?} received={received_at:?} received_monotonic_ns={received_at_ns}"
      )
      .and_then(|()| output.flush())
      .map_err(|error| format!("retain raw input row: {error}"))?;
      let processed_at = Instant::now();
      let processed_at_ns = monotonic_now_ns()?;
      let text = std::str::from_utf8(&line)
        .map_err(|_| "event row is not UTF-8")?
        .trim();
      let fields: Vec<&str> = text.split_ascii_whitespace().collect();
      if fields.is_empty() {
        return Err("blank event row".into());
      }
      match fields[0] {
        "window_begin" if active.is_none() && drain_started.is_none() && fields.len() == 4 => {
          checked_source_event_ns(fields.get(3), received_at_ns, processed_at_ns)?;
          if window_count == MAX_WINDOWS {
            return Err("window count cap exceeded".into());
          }
          window_count += 1;
          let index: u32 = fields[1].parse().map_err(|_| "invalid window index")?;
          let (phase, phase_index) = phase_name(fields[2])?;
          if last_phase.is_none() && phase_index != 0
            || last_phase
              .is_some_and(|previous| phase_index < previous || phase_index > previous + 1)
          {
            return Err("phase sequence skipped or moved backwards".into());
          }
          last_phase = Some(phase_index);
          seen_phases[phase_index] = true;
          ledger
            .begin_window()
            .map_err(|error| format!("begin window: {error:?}"))?;
          let controls_started = Instant::now();
          let controls = match controller.readback() {
            Ok(controls) => controls,
            Err(error) => {
              let failed_at = Instant::now();
              writeln!(output, "window_begin_control_error\tindex={index} started_at={controls_started:?} failed_at={failed_at:?} error={error:?}")
              .map_err(|write_error| format!("write control error: {write_error}"))?;
              let counts = ledger
                .conservation()
                .map_err(|ledger_error| format!("partial ledger: {ledger_error:?}"))?;
              print_counts(&mut output, "partial", &counts)?;
              return Err(format!("window controls: {error}"));
            }
          };
          let controls_finished = Instant::now();
          writeln!(output, "window_start_control_boundary\tindex={index} controls={controls_started:?}..{controls_finished:?} control_snapshot={controls:?}")
          .map_err(|error| format!("write window start controls: {error}"))?;
          let sensors = match sensor.read() {
            Ok(snapshot) => snapshot,
            Err(error) => {
              print_sensor_error(&mut output, "window_begin_sensor_error", &error)?;
              writeln!(output, "window_start_sensor_unavailable\tindex={index} controls={controls_started:?}..{controls_finished:?} control_snapshot={controls:?}")
              .map_err(|write_error| format!("write failed start boundary: {write_error}"))?;
              let counts = ledger
                .conservation()
                .map_err(|ledger_error| format!("partial ledger: {ledger_error:?}"))?;
              print_counts(&mut output, "partial", &counts)?;
              return Err(format!("window sensors: {error:?}"));
            }
          };
          writeln!(
            output,
            "window_start_sensor_boundary\tindex={index} sensor={sensors:?}"
          )
          .map_err(|error| format!("write window start sensors: {error}"))?;
          print_raw_sensors(&mut output, index, "start", &sensors)?;
          if let Err(reason) = safety.check_next(&sensors, MEMORY_MAX) {
            print_boundary(
              &mut output,
              "window_begin_safety_failure",
              index,
              &sensors,
              &controls,
            )?;
            return Err(format!("invocation safety baseline failed: {reason:?}"));
          }
          active = Some(WindowStart {
            index,
            phase: phase.to_owned(),
            controls,
            sensors,
            controls_started,
            controls_finished,
          });
          writeln!(
            output,
            "WINDOW_READY\tindex={index}\tphase={}\ttier={} monotonic_clock=CLOCK_MONOTONIC",
            fields[2],
            controller.tier_index()
          )
          .and_then(|()| output.flush())
          .map_err(|error| format!("window ready: {error}"))?;
        }
        "window_end" if active.is_some() && fields.len() == 3 => {
          checked_source_event_ns(fields.get(2), received_at_ns, processed_at_ns)?;
          let window = active.take().ok_or("window state lost")?;
          let reported: u32 = fields[1]
            .parse()
            .map_err(|_| "invalid ending window index")?;
          if reported != window.index {
            return Err("window end index differs from its start".into());
          }
          let sensors = match sensor.read() {
            Ok(snapshot) => snapshot,
            Err(error) => {
              print_sensor_error(&mut output, "window_end_sensor_error", &error)?;
              let counts = ledger
                .conservation()
                .map_err(|ledger_error| format!("partial ledger: {ledger_error:?}"))?;
              print_counts(&mut output, "partial", &counts)?;
              return Err(format!("window end sensors: {error:?}"));
            }
          };
          if let Err(reason) = safety.check_next(&sensors, MEMORY_MAX) {
            let counts = ledger
              .conservation()
              .map_err(|error| format!("window conservation: {error:?}"))?;
            print_partial_window(&mut output, &window, &sensors, &counts, reason)?;
            return Err(format!("invocation safety baseline failed: {reason:?}"));
          }
          let controls_started = Instant::now();
          let controls = match controller.readback() {
            Ok(controls) => controls,
            Err(error) => {
              let failed_at = Instant::now();
              writeln!(output, "window_end_control_error\tindex={} started_at={controls_started:?} failed_at={failed_at:?} start_controls={:?} start_sensors={:?} sensor_end={sensors:?} error={error:?}", window.index, window.controls, window.sensors)
              .map_err(|write_error| format!("write end control error: {write_error}"))?;
              print_raw_sensors(&mut output, window.index, "end", &sensors)?;
              let counts = ledger
                .conservation()
                .map_err(|ledger_error| format!("partial ledger: {ledger_error:?}"))?;
              print_counts(&mut output, "partial", &counts)?;
              return Err(format!("window end controls: {error}"));
            }
          };
          let controls_finished = Instant::now();
          let counts = match ledger.seal_window() {
            Ok(counts) => counts,
            Err(error) => {
              let counts = ledger
                .conservation()
                .map_err(|ledger_error| format!("invalid window ledger: {ledger_error:?}"))?;
              let evidence = WindowEvidence {
                window: &window,
                end_controls_started: controls_started,
                end_controls_finished: controls_finished,
                end: &sensors,
                end_controls: &controls,
                counts: &counts,
              };
              print_unavailable(
                &mut output,
                &evidence,
                FeedbackUnavailable::Sensor(
                  allocatbelt_bench::adaptive_feedback::ParseError::InvalidTransition,
                ),
              )?;
              return Err(format!("window seal failed: {error:?}"));
            }
          };
          let evidence = WindowEvidence {
            window: &window,
            end_controls_started: controls_started,
            end_controls_finished: controls_finished,
            end: &sensors,
            end_controls: &controls,
            counts: &counts,
          };
          match feedback_for_window(
            &window.sensors,
            &sensors,
            &window.controls,
            &controls,
            MEMORY_MAX,
            ledger.latencies_ns(),
          ) {
            Ok(feedback) => {
              let sample = feedback.sample;
              print_window_evidence(&mut output, &evidence, &feedback)?;
              output
                .flush()
                .map_err(|error| format!("flush sealed window evidence: {error}"))?;
              writeln!(output, "OBSERVE_READY\tindex={}", window.index)
                .and_then(|()| output.flush())
                .map_err(|error| format!("observe handshake: {error}"))?;
              if !read_row(&mut input, &mut line, &mut total_bytes)? {
                return Err("event stream ended before observe_go".into());
              }
              let release_received = Instant::now();
              let release_received_ns = monotonic_now_ns()?;
              writeln!(output, "input_row\tbytes={line:?} received={release_received:?} received_monotonic_ns={release_received_ns}").and_then(|()| output.flush())
              .map_err(|error| format!("retain observe handshake row: {error}"))?;
              let release_processed_ns = monotonic_now_ns()?;
              let release = std::str::from_utf8(&line)
                .map_err(|_| "observe handshake is not UTF-8")?
                .trim();
              let release_fields: Vec<&str> = release.split_ascii_whitespace().collect();
              let release_index = release_fields
                .get(1)
                .ok_or("observe handshake has no window index")?
                .parse::<u32>()
                .map_err(|_| "invalid observe handshake index")?;
              if release_fields.len() != 3
                || release_fields[0] != "observe_go"
                || release_index != window.index
              {
                return Err("observe handshake token did not match the sealed window".into());
              }
              let release_ns = match checked_source_event_ns(
                release_fields.get(2),
                release_received_ns,
                release_processed_ns,
              ) {
                Ok(timestamp) => timestamp,
                Err(error) => {
                  print_unavailable(&mut output, &evidence, FeedbackUnavailable::ObserverDelay)?;
                  writeln!(
                    output,
                    "observe_release_unavailable\tindex={} error={error}",
                    window.index
                  )
                  .map_err(|write_error| format!("write delayed observe result: {write_error}"))?;
                  output.flush().map_err(|write_error| {
                    format!("flush delayed observe result: {write_error}")
                  })?;
                  continue;
                }
              };
              let observe_started = Instant::now();
              if observe_started
                .checked_duration_since(sensors.finished)
                .is_none_or(|delay| delay > MAX_OBSERVE_RELEASE_DELAY)
              {
                print_unavailable(&mut output, &evidence, FeedbackUnavailable::ObserverDelay)?;
                writeln!(output, "observe_release_unavailable\tindex={} source_monotonic_ns={} processed_at={observe_started:?} reason=observer_delay_limit", window.index, release_ns)
                .map_err(|write_error| format!("write delayed observe result: {write_error}"))?;
                output
                  .flush()
                  .map_err(|write_error| format!("flush delayed observe result: {write_error}"))?;
                continue;
              }
              last_real_sample = Some(sample);
              let observed = controller.observe(sample);
              let observe_finished = Instant::now();
              match observed {
              Ok(decision) => writeln!(output, "adaptive_decision\tcalled_at={observe_started:?} finished_at={observe_finished:?} result={decision:?}").map_err(|error| format!("write decision: {error}"))?,
              Err(error) => {
                writeln!(output, "adaptive_apply_error\tindex={} faulted={} called_at={observe_started:?} finished_at={observe_finished:?} error={error:?}", window.index, controller.is_faulted())
                  .map_err(|error| format!("write apply error: {error}"))?;
                print_counts(&mut output, "faulted_window", &counts)?;
              }
            }
            }
            Err(FeedbackUnavailable::NoCompletedResponses) => {
              print_unavailable(
                &mut output,
                &evidence,
                FeedbackUnavailable::NoCompletedResponses,
              )?;
            }
            Err(reason) => {
              print_unavailable(&mut output, &evidence, reason)?;
              return Err(format!("window was not eligible for feedback: {reason:?}"));
            }
          }
          output
            .flush()
            .map_err(|error| format!("window report flush: {error}"))?;
        }
        "drain_begin" if active.is_none() && drain_started.is_none() && fields.len() == 2 => {
          if !seen_phases.iter().all(|seen| *seen) {
            return Err("final drain began before every frozen phase had a sampled window".into());
          }
          let millis: u64 = fields[1].parse().map_err(|_| "invalid drain deadline")?;
          let duration = Duration::from_millis(millis);
          if duration.is_zero() || duration > MAX_DRAIN {
            return Err("drain deadline must be in 1..=10000 ms".into());
          }
          ledger
            .begin_window()
            .map_err(|error| format!("begin final drain: {error:?}"))?;
          let drain_commit_ns = monotonic_now_ns()?;
          ledger
            .seal_offers(drain_commit_ns, drain_commit_ns)
            .map_err(|error| format!("seal final drain offers: {error:?}"))?;
          ledger
            .acknowledge_offers(drain_commit_ns)
            .map_err(|error| format!("acknowledge final drain offers: {error:?}"))?;
          drain_started = Some((Instant::now(), duration));
          writeln!(
            output,
            "DRAIN_READY\tdeadline_ms={millis} ack_watermark_ns={drain_commit_ns}"
          )
          .and_then(|()| output.flush())
          .map_err(|error| format!("drain ready: {error}"))?;
        }
        "drain_end" if active.is_none() && drain_started.is_some() && fields.len() == 1 => {
          let (started, limit) = drain_started.ok_or("drain state lost")?;
          let controls_started = Instant::now();
          let drain_control_result = controller.readback();
          let controls_finished = Instant::now();
          let drain_sensor_result = sensor.read();
          let elapsed = Instant::now()
            .checked_duration_since(started)
            .ok_or("drain clock regressed")?;
          let drain_sensors = match drain_sensor_result {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
              print_sensor_error(&mut output, "final_drain_sensor_error", &error)?;
              None
            }
          };
          let drain_controls = match drain_control_result {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
              writeln!(output, "final_drain_control_error\tcalled_at={controls_started:?} finished_at={controls_finished:?} error={error:?}")
              .map_err(|write_error| format!("write final drain control error: {write_error}"))?;
              None
            }
          };
          if let Some(sensors) = &drain_sensors {
            writeln!(output, "final_drain_sensor_boundary\tsensor={sensors:?}")
              .map_err(|error| format!("write final drain sensor boundary: {error}"))?;
            print_raw_sensors(&mut output, window_count as u32, "final_drain", sensors)?;
          }
          if let Some(controls) = &drain_controls {
            writeln!(output, "final_drain_control_boundary\tcontrols={controls_started:?}..{controls_finished:?} control_snapshot={controls:?}")
            .map_err(|error| format!("write final drain control boundary: {error}"))?;
          }
          if let (Some(sensors), Some(controls)) = (&drain_sensors, &drain_controls) {
            writeln!(output, "final_drain_boundary\tcontrols={controls_started:?}..{controls_finished:?} control_snapshot={controls:?} sensor={sensors:?}")
            .map_err(|error| format!("write final drain boundary: {error}"))?;
            let safety_error = safety.check_next(sensors, MEMORY_MAX).err().or_else(|| {
              (controls.memory_max != Limit::Value(MEMORY_MAX))
                .then_some(FeedbackUnavailable::OriginalMemoryMax)
            });
            if let Some(reason) = safety_error {
              writeln!(output, "final_drain_safety_failed\treason={reason:?}")
                .map_err(|error| format!("write final drain safety result: {error}"))?;
              let counts = ledger
                .conservation()
                .map_err(|error| format!("final drain conservation: {error:?}"))?;
              print_counts(&mut output, "final_drain_failed", &counts)?;
              return Err(format!("final drain safety boundary failed: {reason:?}"));
            }
          } else {
            writeln!(output, "final_drain_safety_unavailable\tcontrols={controls_started:?}..{controls_finished:?} sensors_available={} controls_available={}", drain_sensors.is_some(), drain_controls.is_some())
            .map_err(|error| format!("write unavailable final drain boundary: {error}"))?;
            let counts = ledger
              .conservation()
              .map_err(|error| format!("final drain conservation: {error:?}"))?;
            print_counts(&mut output, "final_drain_failed", &counts)?;
            return Err("final drain cannot establish its final safety boundary".into());
          }
          let counts = ledger
            .seal_window()
            .map_err(|error| format!("drain conservation: {error:?}"))?;
          if elapsed > limit
            || counts.pending_after != 0
            || counts.not_attempted != 0
            || counts.attempt_pending != 0
          {
            print_counts(&mut output, "final_drain_failed", &counts)?;
            return Err("final drain missed its deadline or retained unfinished work".into());
          }
          print_items(&mut output, &counts)?;
          writeln!(output, "final_drain\telapsed_ns={} pending_after=0 not_attempted={} attempt_pending={} completed={} errors={} cancelled={}", elapsed.as_nanos(), counts.not_attempted, counts.attempt_pending, counts.completed, counts.errors, counts.cancelled)
          .map_err(|error| format!("drain report: {error}"))?;
          drain_started = None;
          drain_complete = true;
        }
        "fault_guard" if active.is_none() && drain_started.is_none() && fields.len() == 1 => {
          let sample = last_real_sample.ok_or("fault guard has no prior real feedback sample")?;
          match controller.observe(sample) {
            Err(error) => writeln!(
              output,
              "fault_guard_reused_actual_sample\tfaulted={} error={error:?}",
              controller.is_faulted()
            ),
            Ok(decision) => writeln!(output, "fault_guard_unexpected_decision\t{decision:?}"),
          }
          .map_err(|error| format!("write fault guard result: {error}"))?;
        }
        "resume_attempt" if active.is_none() && drain_started.is_none() && fields.len() == 2 => {
          let resume_started = Instant::now();
          let resume_result = controller.resume_from_readback(resume_started);
          let resume_finished = Instant::now();
          match resume_result {
            Ok(tier) => writeln!(
              output,
              "explicit_resume\tlabel={} result=ok tier={tier}",
              fields[1]
            ),
            Err(error) => writeln!(
              output,
              "explicit_resume\tlabel={} result=error error={error:?} faulted={}",
              fields[1],
              controller.is_faulted()
            ),
          }
          .map_err(|error| format!("write resume result: {error}"))?;
          let readback_started = Instant::now();
          let resume_readback = controller.readback();
          let readback_finished = Instant::now();
          writeln!(output, "explicit_resume_call_chronology\tcalled_at={resume_started:?} returned_at={resume_finished:?}")
          .map_err(|error| format!("write resume call chronology: {error}"))?;
          writeln!(output, "explicit_resume_readback_chronology\tstarted_at={readback_started:?} finished_at={readback_finished:?} result={resume_readback:?}")
          .map_err(|error| format!("write resume readback chronology: {error}"))?;
        }
        "offers_seal" if active.is_some() && fields.len() == 3 && drain_started.is_none() => {
          let window = active
            .as_ref()
            .ok_or("window state lost before offer seal")?;
          let index: u32 = fields[1]
            .parse()
            .map_err(|_| "invalid offer seal window index")?;
          if index != window.index {
            return Err("offer seal index differs from active window".into());
          }
          let source_seal_ns =
            checked_source_event_ns(fields.get(2), received_at_ns, processed_at_ns)?;
          ledger
            .seal_offers(source_seal_ns, processed_at_ns)
            .map_err(|error| format!("seal offered schedule: {error:?}"))?;
          let ack_watermark_ns = monotonic_now_ns()?;
          ledger
            .acknowledge_offers(ack_watermark_ns)
            .map_err(|error| format!("acknowledge offered schedule: {error:?}"))?;
          writeln!(output, "OFFERS_SEALED\tindex={index} source_clock=CLOCK_MONOTONIC source_seal_ns={source_seal_ns} commit_ns={processed_at_ns} ack_watermark_ns={ack_watermark_ns}")
          .and_then(|()| output.flush())
          .map_err(|error| format!("write offer seal: {error}"))?;
        }
        "offer" | "arrive" | "attempt" | "accept" | "reject_full" | "reject_resource" | "start"
        | "complete" | "error" | "cancel"
          if active.is_some() || drain_started.is_some() =>
        {
          if let Some((started, limit)) = drain_started
            && processed_at
              .checked_duration_since(started)
              .is_none_or(|elapsed| elapsed > limit)
          {
            return Err("final drain event exceeded its deadline".into());
          }
          if let Err(error) = apply_event(
            &mut ledger,
            &fields,
            received_at_ns,
            processed_at_ns,
            drain_started.is_some(),
          ) {
            let counts = ledger
              .conservation()
              .map_err(|ledger_error| format!("error ledger: {ledger_error:?}"))?;
            print_counts(&mut output, "partial", &counts)?;
            return Err(error);
          }
        }
        _ => {
          return Err(format!(
            "event not allowed in current protocol state: {text}"
          ));
        }
      }
      if drain_complete {
        let mut trailing = [0u8; 1];
        if input
          .read(&mut trailing)
          .map_err(|error| format!("post-drain input read: {error}"))?
          != 0
        {
          return Err("input continued after drain_end".into());
        }
        break;
      }
    }
    if active.is_some() || drain_started.is_some() || !drain_complete {
      if let Ok(counts) = ledger.conservation() {
        let _ = print_counts(&mut output, "partial", &counts);
      }
      return Err("event stream ended before a complete final drain".into());
    }
    Ok(())
  })();
  if result.is_err() {
    if let Ok(counts) = ledger.conservation() {
      let _ = print_counts(&mut output, "exit_partial", &counts);
    }
    let _ = output.flush();
  }
  result
}

fn cpu_max(quota_us: u64) -> Result<CpuMax, String> {
  let quota = NonZeroU64::new(quota_us).ok_or("quota must be finite and nonzero")?;
  let period = NonZeroU64::new(PERIOD_US).ok_or("period must be nonzero")?;
  Ok(CpuMax::new(quota, period))
}

fn read_row(
  input: &mut impl BufRead,
  line: &mut Vec<u8>,
  total: &mut usize,
) -> Result<bool, String> {
  line.clear();
  loop {
    let (take, newline, eof) = {
      let buffer = input
        .fill_buf()
        .map_err(|error| format!("event stream read: {error}"))?;
      if buffer.is_empty() {
        (0, false, true)
      } else {
        let take = buffer
          .iter()
          .position(|byte| *byte == b'\n')
          .map_or(buffer.len(), |index| index + 1);
        if line
          .len()
          .checked_add(take)
          .is_none_or(|length| length > MAX_LINE_BYTES)
        {
          return Err("event row exceeded its bounded size".into());
        }
        line.extend_from_slice(&buffer[..take]);
        (take, buffer[take - 1] == b'\n', false)
      }
    };
    if eof {
      return Ok(!line.is_empty());
    }
    input.consume(take);
    *total = total
      .checked_add(take)
      .ok_or("event input byte count overflow")?;
    if *total > MAX_INPUT_BYTES {
      return Err("event stream exceeded its bounded input size".into());
    }
    if newline {
      return Ok(true);
    }
  }
}

fn phase_name(value: &str) -> Result<(&'static str, usize), String> {
  match value {
    "warm" => Ok(("warm", 0)),
    "low" => Ok(("low", 1)),
    "cpu" => Ok(("cpu", 2)),
    "memory" => Ok(("memory", 3)),
    "overload" => Ok(("overload", 4)),
    "recovery" => Ok(("recovery", 5)),
    "drift" => Ok(("drift", 6)),
    "permission" => Ok(("permission", 7)),
    _ => Err("phase is not in the frozen phase set".into()),
  }
}

fn monotonic_now_ns() -> Result<u64, String> {
  let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
  let seconds = u64::try_from(time.tv_sec).map_err(|_| "negative monotonic clock")?;
  let nanoseconds = u64::try_from(time.tv_nsec).map_err(|_| "negative monotonic nanoseconds")?;
  seconds
    .checked_mul(1_000_000_000)
    .and_then(|value| value.checked_add(nanoseconds))
    .ok_or_else(|| "CLOCK_MONOTONIC nanoseconds overflow".into())
}

fn source_event_ns(value: Option<&&str>, received_ns: u64) -> Result<u64, String> {
  let event_ns: u64 = value
    .ok_or("missing source CLOCK_MONOTONIC timestamp")?
    .parse()
    .map_err(|_| "invalid source CLOCK_MONOTONIC timestamp")?;
  check_source_event_delay(event_ns, received_ns)?;
  Ok(event_ns)
}

fn checked_source_event_ns(
  value: Option<&&str>,
  received_ns: u64,
  processed_ns: u64,
) -> Result<u64, String> {
  let event_ns = source_event_ns(value, received_ns)?;
  check_source_event_delay(event_ns, processed_ns)?;
  Ok(event_ns)
}

fn check_source_event_delay(event_ns: u64, received_ns: u64) -> Result<(), String> {
  let delay_ns = received_ns
    .checked_sub(event_ns)
    .ok_or("source event timestamp is in the future")?;
  if delay_ns > MAX_SOURCE_EVENT_DELAY_NS {
    return Err(format!(
      "source event arrived {delay_ns} ns late; limit is {MAX_SOURCE_EVENT_DELAY_NS} ns"
    ));
  }
  Ok(())
}

fn parse_id(value: Option<&&str>) -> Result<u64, String> {
  value
    .ok_or("missing work ID")?
    .parse()
    .map_err(|_| "invalid work ID".into())
}

fn apply_event(
  ledger: &mut WindowLedger,
  fields: &[&str],
  received_ns: u64,
  processed_ns: u64,
  draining: bool,
) -> Result<(), String> {
  let id = || parse_id(fields.get(1));
  // Event values use the same host CLOCK_MONOTONIC domain as the receipt clock.
  if draining && !matches!(fields[0], "start" | "complete" | "error" | "cancel") {
    return Err("final drain permits starts and terminal dispositions only".into());
  }
  match fields[0] {
    "offer" if fields.len() == 4 && !draining => {
      let scheduled: u64 = fields[2]
        .parse()
        .map_err(|_| "invalid scheduled CLOCK_MONOTONIC timestamp")?;
      ledger
        .offer(
          id()?,
          scheduled,
          fields[3].parse().map_err(|_| "invalid expected checksum")?,
        )
        .map_err(|error| format!("offer row: {error:?}"))?;
    }
    "arrive" if fields.len() == 3 && !draining => {
      ledger
        .arrived(
          id()?,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        )
        .map_err(|error| format!("arrival row: {error:?}"))?;
    }
    "attempt" if fields.len() == 3 && !draining => {
      ledger
        .attempt(
          id()?,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        )
        .map_err(|error| format!("attempt row: {error:?}"))?;
    }
    "accept" if fields.len() == 3 && !draining => {
      ledger
        .accept(
          id()?,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        )
        .map_err(|error| format!("accept row: {error:?}"))?;
    }
    "reject_full" if fields.len() == 3 && !draining => {
      ledger
        .reject(
          id()?,
          Disposition::RejectedFull,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        )
        .map_err(|error| format!("reject row: {error:?}"))?;
    }
    "reject_resource" if fields.len() == 3 && !draining => {
      ledger
        .reject(
          id()?,
          Disposition::RejectedResource,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        )
        .map_err(|error| format!("reject row: {error:?}"))?;
    }
    "start" if fields.len() == 3 => {
      ledger
        .started(
          id()?,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        )
        .map_err(|error| format!("start row: {error:?}"))?;
    }
    "complete" if fields.len() == 4 => {
      ledger
        .complete(
          id()?,
          checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
          fields[3]
            .parse()
            .map_err(|_| "invalid completion checksum")?,
        )
        .map_err(|error| format!("completion row: {error:?}"))?;
    }
    "error" if fields.len() == 3 => ledger
      .fail(
        id()?,
        checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        false,
      )
      .map_err(|error| format!("error row: {error:?}"))?,
    "cancel" if fields.len() == 3 => ledger
      .fail(
        id()?,
        checked_source_event_ns(fields.get(2), received_ns, processed_ns)?,
        true,
      )
      .map_err(|error| format!("cancel row: {error:?}"))?,
    _ => return Err("malformed work event".into()),
  }
  Ok(())
}

fn print_counts(output: &mut impl Write, label: &str, counts: &Conservation) -> Result<(), String> {
  writeln!(output, "{label}\tscope=partition_totals_cumulative,pending_before_checksum_lateness_window,pending_after_cumulative offered={} attempted={} not_attempted={} rejected_full={} rejected_resource={} accepted={} attempt_pending={} completed={} errors={} cancelled={} pending_before={} pending_after={} delayed_unattempted={} checksum={} expected_checksum={} lateness_mean_ns={} lateness_max_ns={}",
    counts.offered, counts.attempted, counts.not_attempted, counts.rejected_full,
    counts.rejected_resource, counts.accepted, counts.attempt_pending, counts.completed, counts.errors,
    counts.cancelled, counts.pending_before, counts.pending_after,
    counts.delayed_unattempted, counts.checksum, counts.expected_checksum,
    counts.producer_lateness_mean_ns, counts.producer_lateness_max_ns)
    .map_err(|error| format!("write counts: {error}"))?;
  if matches!(
    label,
    "partial" | "exit_partial" | "faulted_window" | "safety_failed_window" | "final_drain_failed"
  ) {
    print_items(output, counts)?;
  }
  Ok(())
}

fn print_items(output: &mut impl Write, counts: &Conservation) -> Result<(), String> {
  for item in &counts.items {
    writeln!(output, "work_item\tid={} offered_epoch={} source_seal_ns={:?} commit_ns={:?} dispatch_ack_ns={:?} scheduled_monotonic_ns={} arrived_monotonic_ns={:?} attempted_monotonic_ns={:?} admitted_monotonic_ns={:?} started_monotonic_ns={:?} finished_monotonic_ns={:?} disposition={:?}",
      item.id, item.offered_epoch, item.source_seal_ns, item.commit_ns, item.dispatch_ack_ns,
      item.scheduled_ns, item.offered_ns, item.attempted_ns, item.admitted_ns,
      item.started_ns, item.finished_ns, item.disposition)
      .map_err(|error| format!("write per-ID chronology: {error}"))?;
  }
  Ok(())
}

fn print_window_evidence(
  output: &mut impl Write,
  evidence: &WindowEvidence<'_>,
  feedback: &WindowFeedback,
) -> Result<(), String> {
  let WindowEvidence {
    window,
    end_controls_started,
    end_controls_finished,
    end,
    end_controls,
    counts,
  } = evidence;
  print_counts(output, "window", counts)?;
  writeln!(output, "window_identity\tindex={} phase={} source_clock=CLOCK_MONOTONIC control_start={:?}..{:?} control_start_snapshot={:?} control_end={:?}..{:?} control_end_snapshot={:?} sensor_start={:?}..{:?} sensor_end={:?}..{:?} group={:?}",
    window.index, window.phase, window.controls_started, window.controls_finished, window.controls,
    end_controls_started, end_controls_finished, end_controls, window.sensors.started, window.sensors.finished,
    end.started, end.finished, end.group)
    .map_err(|error| format!("write chronology: {error}"))?;
  writeln!(
    output,
    "latency\tn={} p50_ns={} p95_ns={} p99_ns={}",
    feedback.latency.completed,
    feedback.latency.p50_ns,
    feedback.latency.p95_ns,
    feedback.latency.p99_ns
  )
  .map_err(|error| format!("write latency: {error}"))?;
  writeln!(output, "cpu\tusage_start_usec={} usage_end_usec={} elapsed_ns={} elapsed_usec={} read_point_uncertainty_bound_ns={} quota_us={} period_us={} raw_basis_points={} controller_basis_points={} saturated={}",
    window.sensors.parsed.cpu.usage_usec, end.parsed.cpu.usage_usec,
    feedback.cpu_elapsed_ns, feedback.cpu_elapsed_usec, feedback.cpu_uncertainty_bound_ns, end.parsed.cpu_max.quota_us,
    end.parsed.cpu_max.period_us, feedback.cpu.raw_basis_points,
    feedback.cpu.controller_basis_points, feedback.cpu.saturated)
    .map_err(|error| format!("write CPU sample: {error}"))?;
  writeln!(output, "memory\tcurrent={} fixed_original_max={} high={} raw_basis_points={} high_delta={} max_start={} max_end={} oom_start={} oom_end={} oom_kill_start={} oom_kill_end={}",
    feedback.memory_current, feedback.original_memory_max, feedback.memory_high,
    feedback.memory_raw_basis_points, feedback.memory_high_event_delta,
    window.sensors.parsed.events.max, end.parsed.events.max,
    window.sensors.parsed.events.oom, end.parsed.events.oom,
    window.sensors.parsed.events.oom_kill, end.parsed.events.oom_kill)
    .map_err(|error| format!("write memory sample: {error}"))?;
  writeln!(output, "psi_usec\tcpu_some={} cpu_full={} memory_some={} memory_full={} cpu_elapsed_ns={} cpu_uncertainty_bound_ns={} memory_elapsed_ns={} memory_uncertainty_bound_ns={} cpu_some_bp={} cpu_full_bp={} memory_some_bp={} memory_full_bp={}",
    feedback.psi.cpu_some_delta_usec, feedback.psi.cpu_full_delta_usec,
    feedback.psi.memory_some_delta_usec, feedback.psi.memory_full_delta_usec,
    feedback.psi.cpu_elapsed_ns, feedback.psi.cpu_uncertainty_bound_ns,
    feedback.psi.memory_elapsed_ns, feedback.psi.memory_uncertainty_bound_ns,
    feedback.psi.cpu_some_stall_basis_points, feedback.psi.cpu_full_stall_basis_points,
    feedback.psi.memory_some_stall_basis_points, feedback.psi.memory_full_stall_basis_points)
    .map_err(|error| format!("write PSI sample: {error}"))?;
  print_raw_sensors(output, window.index, "start", &window.sensors)?;
  print_raw_sensors(output, window.index, "end", end)?;
  Ok(())
}

fn print_raw_sensors(
  output: &mut impl Write,
  index: u32,
  boundary: &str,
  snapshot: &SensorSnapshot,
) -> Result<(), String> {
  for file in &snapshot.files {
    writeln!(output, "sensor_file\tindex={index} boundary={boundary} name={} read_started={:?} read_finished={:?} digest64={:016x} identity={:?} bytes={:?}",
      file.name, file.read_started, file.read_finished, file.digest64, file.identity, file.bytes)
      .map_err(|error| format!("write raw sensor file: {error}"))?;
  }
  Ok(())
}

fn print_unavailable(
  output: &mut impl Write,
  evidence: &WindowEvidence<'_>,
  reason: FeedbackUnavailable,
) -> Result<(), String> {
  let WindowEvidence {
    window,
    end_controls_started,
    end_controls_finished,
    end,
    end_controls,
    counts,
  } = evidence;
  print_counts(output, "unavailable_window", counts)?;
  writeln!(output, "feedback_unavailable\tindex={} phase={} reason={reason:?} observe_called=false control_start={:?}..{:?} control_start_snapshot={:?} control_end={:?}..{:?} control_end_snapshot={:?} sensor_start={:?}..{:?} sensor_end={:?}..{:?}",
    window.index, window.phase, window.controls_started, window.controls_finished, window.controls,
    end_controls_started, end_controls_finished, end_controls, window.sensors.started,
    window.sensors.finished, end.started, end.finished)
    .map_err(|error| format!("write unavailable window: {error}"))?;
  print_raw_sensors(output, window.index, "start", &window.sensors)?;
  print_raw_sensors(output, window.index, "end", end)
}

fn print_boundary(
  output: &mut impl Write,
  label: &str,
  index: u32,
  sensors: &SensorSnapshot,
  controls: &allocatbelt::runtime::cgroup::CgroupSnapshot,
) -> Result<(), String> {
  writeln!(
    output,
    "{label}\tindex={index} sensor={sensors:?} controls={controls:?}"
  )
  .map_err(|error| format!("write boundary evidence: {error}"))?;
  print_raw_sensors(output, index, "boundary", sensors)
}

fn print_sensor_error(
  output: &mut impl Write,
  label: &str,
  error: &SensorError,
) -> Result<(), String> {
  match error {
    SensorError::Partial(capture) => {
      writeln!(output, "{label}\tgroup={:?} started={:?} failed_at={:?} failed_name={} error_kind={:?} errno={:?} observed_bytes={} error={} digest64={:016x} raw_prefix={:?}",
        capture.group, capture.started, capture.failed_at, capture.failed_name,
        capture.error_kind, capture.native_errno, capture.observed_bytes, capture.error, capture.digest64, capture.raw_prefix)
        .map_err(|write_error| format!("write partial sensor read: {write_error}"))?;
      for file in &capture.files {
        writeln!(output, "partial_sensor_file\tname={} read_started={:?} read_finished={:?} digest64={:016x} identity={:?} bytes={:?}",
          file.name, file.read_started, file.read_finished, file.digest64, file.identity, file.bytes)
          .map_err(|write_error| format!("write retained sensor file: {write_error}"))?;
      }
      Ok(())
    }
    other => writeln!(output, "{label}\terror={other:?}")
      .map_err(|write_error| format!("write sensor error: {write_error}")),
  }
}

fn print_partial_window(
  output: &mut impl Write,
  window: &WindowStart,
  end: &SensorSnapshot,
  counts: &Conservation,
  reason: FeedbackUnavailable,
) -> Result<(), String> {
  print_counts(output, "safety_failed_window", counts)?;
  writeln!(output, "safety_failed_window\tindex={} phase={} reason={reason:?} start_controls={:?} start_sensors={:?} end_sensors={:?}",
    window.index, window.phase, window.controls, window.sensors, end)
    .map_err(|error| format!("write partial safety evidence: {error}"))?;
  print_raw_sensors(output, window.index, "start", &window.sensors)?;
  print_raw_sensors(output, window.index, "end", end)
}

fn main() {
  if let Err(error) = run() {
    eprintln!("bench-adaptive-pressure: {error}");
    std::process::exit(1);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use allocatbelt_bench::adaptive_feedback::ParseError;
  use std::io::Cursor;

  #[test]
  fn source_clock_rejects_future_and_stale_events() {
    assert_eq!(check_source_event_delay(100, 100), Ok(()));
    assert_eq!(
      check_source_event_delay(100, 100 + MAX_SOURCE_EVENT_DELAY_NS),
      Ok(())
    );
    assert!(check_source_event_delay(101, 100).is_err());
    assert!(check_source_event_delay(100, 101 + MAX_SOURCE_EVENT_DELAY_NS).is_err());
  }

  #[test]
  fn bounded_input_reader_accepts_limit_and_rejects_longer_rows() {
    let mut exact = Cursor::new(
      vec![b'x'; MAX_LINE_BYTES - 1]
        .into_iter()
        .chain(*b"\n")
        .collect::<Vec<_>>(),
    );
    let mut line = Vec::new();
    let mut total = 0;
    assert!(read_row(&mut exact, &mut line, &mut total).unwrap());
    assert_eq!(line.len(), MAX_LINE_BYTES);

    let mut oversized = Cursor::new(vec![b'x'; MAX_LINE_BYTES + 1]);
    let mut line = Vec::new();
    let mut total = 0;
    assert!(read_row(&mut oversized, &mut line, &mut total).is_err());
  }

  #[test]
  fn explicit_rejection_and_queued_start_are_valid_during_drain() {
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, 100, 7).unwrap();
    ledger.seal_offers(100, 100).unwrap();
    ledger.acknowledge_offers(100).unwrap();
    apply_event(&mut ledger, &["arrive", "1", "101"], 101, 101, false).unwrap();
    apply_event(&mut ledger, &["attempt", "1", "102"], 102, 102, false).unwrap();
    apply_event(&mut ledger, &["accept", "1", "103"], 103, 103, false).unwrap();
    ledger.seal_window().unwrap();

    ledger.begin_window().unwrap();
    ledger.seal_offers(104, 104).unwrap();
    ledger.acknowledge_offers(104).unwrap();
    apply_event(&mut ledger, &["start", "1", "104"], 104, 104, true).unwrap();
    apply_event(&mut ledger, &["complete", "1", "105", "7"], 105, 105, true).unwrap();
    let counts = ledger.conservation().unwrap();
    assert_eq!(
      (
        counts.pending_before,
        counts.pending_after,
        counts.completed
      ),
      (1, 0, 1)
    );
    assert!(apply_event(&mut ledger, &["offer", "2", "106", "8"], 106, 106, true).is_err());
    assert!(apply_event(&mut ledger, &["accept", "2", "107"], 107, 107, true).is_err());
  }

  #[test]
  fn buffered_carryover_uses_its_original_ack_in_next_window_and_drain() {
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, 120, 7).unwrap();
    ledger.seal_offers(110, 115).unwrap();
    ledger.acknowledge_offers(120).unwrap();
    apply_event(&mut ledger, &["arrive", "1", "121"], 121, 121, false).unwrap();
    apply_event(&mut ledger, &["attempt", "1", "122"], 122, 122, false).unwrap();
    apply_event(&mut ledger, &["accept", "1", "123"], 123, 123, false).unwrap();
    apply_event(&mut ledger, &["start", "1", "124"], 124, 124, false).unwrap();
    ledger.seal_window().unwrap();

    ledger.begin_window().unwrap();
    ledger.seal_offers(180, 185).unwrap();
    ledger.acknowledge_offers(190).unwrap();
    apply_event(&mut ledger, &["complete", "1", "150", "7"], 200, 200, false).unwrap();
    let counts = ledger.conservation().unwrap();
    assert_eq!(
      (counts.offered, counts.completed, counts.pending_after),
      (1, 1, 0)
    );
    assert_eq!(ledger.latencies_ns(), &[30]);
    assert_eq!(
      allocatbelt_bench::adaptive_feedback::latency_summary(ledger.latencies_ns()).unwrap(),
      allocatbelt_bench::adaptive_feedback::LatencySummary {
        completed: 1,
        p50_ns: 30,
        p95_ns: 30,
        p99_ns: 30
      }
    );
    let item = &counts.items[0];
    assert_eq!(
      (item.source_seal_ns, item.commit_ns, item.dispatch_ack_ns),
      (Some(110), Some(115), Some(120))
    );
    assert_eq!(
      (item.started_ns, item.finished_ns, item.disposition),
      (Some(124), Some(150), Disposition::Completed)
    );

    let mut drain = WindowLedger::new(4).unwrap();
    drain.begin_window().unwrap();
    drain.offer(2, 120, 9).unwrap();
    drain.seal_offers(110, 115).unwrap();
    drain.acknowledge_offers(120).unwrap();
    apply_event(&mut drain, &["arrive", "2", "121"], 121, 121, false).unwrap();
    apply_event(&mut drain, &["attempt", "2", "122"], 122, 122, false).unwrap();
    apply_event(&mut drain, &["accept", "2", "123"], 123, 123, false).unwrap();
    drain.seal_window().unwrap();
    drain.begin_window().unwrap();
    drain.seal_offers(180, 185).unwrap();
    drain.acknowledge_offers(190).unwrap();
    apply_event(&mut drain, &["start", "2", "124"], 200, 200, true).unwrap();
    apply_event(&mut drain, &["complete", "2", "150", "9"], 200, 200, true).unwrap();
    let drained = drain.conservation().unwrap();
    assert_eq!(
      (
        drained.pending_before,
        drained.pending_after,
        drained.completed
      ),
      (1, 0, 1)
    );
    assert_eq!(drain.latencies_ns(), &[30]);
    assert_eq!(
      allocatbelt_bench::adaptive_feedback::latency_summary(drain.latencies_ns()).unwrap(),
      allocatbelt_bench::adaptive_feedback::LatencySummary {
        completed: 1,
        p50_ns: 30,
        p95_ns: 30,
        p99_ns: 30
      }
    );
    assert_eq!(
      (drained.items[0].started_ns, drained.items[0].finished_ns),
      (Some(124), Some(150))
    );
    assert_eq!(
      (
        drained.items[0].source_seal_ns,
        drained.items[0].commit_ns,
        drained.items[0].dispatch_ack_ns
      ),
      (Some(110), Some(115), Some(120))
    );
  }

  #[test]
  fn new_offer_callbacks_require_their_own_acknowledgement() {
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, 100, 1).unwrap();
    ledger.seal_offers(100, 105).unwrap();
    assert_eq!(ledger.arrived(1, 106), Err(ParseError::InvalidTransition));
    ledger.acknowledge_offers(110).unwrap();
    assert_eq!(ledger.arrived(1, 109), Err(ParseError::NonMonotonicTime));
    assert_eq!(ledger.arrived(1, 110), Ok(()));
  }

  #[test]
  fn mixed_current_and_carried_completions_keep_the_queued_tail_in_p99() {
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, 120, 7).unwrap();
    ledger.seal_offers(110, 115).unwrap();
    ledger.acknowledge_offers(120).unwrap();
    apply_event(&mut ledger, &["arrive", "1", "121"], 121, 121, false).unwrap();
    apply_event(&mut ledger, &["attempt", "1", "122"], 122, 122, false).unwrap();
    apply_event(&mut ledger, &["accept", "1", "123"], 123, 123, false).unwrap();
    apply_event(&mut ledger, &["start", "1", "124"], 124, 124, false).unwrap();
    ledger.seal_window().unwrap();

    ledger.begin_window().unwrap();
    ledger.offer(2, 191, 9).unwrap();
    ledger.seal_offers(180, 185).unwrap();
    ledger.acknowledge_offers(190).unwrap();
    apply_event(&mut ledger, &["arrive", "2", "191"], 191, 191, false).unwrap();
    apply_event(&mut ledger, &["attempt", "2", "192"], 192, 192, false).unwrap();
    apply_event(&mut ledger, &["accept", "2", "193"], 193, 193, false).unwrap();
    apply_event(&mut ledger, &["start", "2", "194"], 194, 194, false).unwrap();
    apply_event(&mut ledger, &["complete", "2", "196", "9"], 196, 196, false).unwrap();
    apply_event(&mut ledger, &["complete", "1", "250", "7"], 300, 300, false).unwrap();

    let counts = ledger.conservation().unwrap();
    assert_eq!(
      (counts.offered, counts.completed, counts.pending_after),
      (2, 2, 0)
    );
    assert_eq!(ledger.latencies_ns(), &[5, 130]);
    assert_eq!(
      allocatbelt_bench::adaptive_feedback::latency_summary(ledger.latencies_ns()).unwrap(),
      allocatbelt_bench::adaptive_feedback::LatencySummary {
        completed: 2,
        p50_ns: 5,
        p95_ns: 130,
        p99_ns: 130
      }
    );
    assert_eq!(
      (counts.items[0].finished_ns, counts.items[0].dispatch_ack_ns),
      (Some(250), Some(120))
    );
    assert_eq!(
      (counts.items[1].finished_ns, counts.items[1].dispatch_ack_ns),
      (Some(196), Some(190))
    );
  }
}
