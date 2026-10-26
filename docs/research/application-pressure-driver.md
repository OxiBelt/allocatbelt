# Bounded external application pressure lane

The pressure driver supplies a finite CPU, block-I/O and IPv4 loopback load to
one application process. It is a prospective harness component. Implementing
the driver does not enable campaign execution or qualify an allocator/runtime.

The SourceV5 three-hour soak runner starts this driver first, validates its
measured readiness marker, and only then starts the soak application. The
application launch binding is atomically published after `Popen` with the
observed PID/start ticks, binary, affinity, network namespace, cwd and TMPDIR.
See [`application-soak-readback.md`](application-soak-readback.md) for the
independent soak composite and its separate pressure and feedback proofs.

Every application process receives its own canonical recipe and fresh driver
session. Pair members use distinct binary hashes, process nonces and launch
records, while sharing one `condition_id`, the exact schedule, pressure
calibration, selected readiness thresholds, host boot identity, CPU sets,
storage backing and network namespace. Their `condition_sha256` values must
match before the pair can be compared. The source manifest, application
binary, policy, application-byte-capacity calibration, pressure-contention
calibration, pressure driver and independent reader each have separate raw
SHA-256 bindings. The two calibration inputs are distinct fields and distinct
artifacts; pressure readiness never substitutes for app-byte capacity
calibration.

The application-capacity input is the exact TSV artifact consumed by the
runtime. Bind its raw bytes; the pressure calibration has its own JSON format.

The request schema is `allocatbelt.application-pressure-request.v1`. A
calibration request has exactly `schema`, `identity`, `files`, `process`,
`storage` and `schedule`. A freeze request adds exactly
`pressure_calibration` and `readiness_thresholds`. Both request forms use these
fields:

```json
{
  "schema": "allocatbelt.application-pressure-request.v1",
  "identity": {
    "host_id": "native-host-id",
    "run_id": "pair-member-run-id",
    "pair_id": "matched-pair-id",
    "condition_id": "shared-condition-id",
    "member": "member-a",
    "nonce": "32-lowercase-hex-characters",
    "allocator": "allocator-id",
    "executor": "executor-id"
  },
  "files": {
    "source_manifest": {"path": "/absolute/source-manifest.json", "sha256": "64-lowercase-hex-characters"},
    "application_binary": {"path": "/absolute/application", "sha256": "64-lowercase-hex-characters"},
    "policy": {"path": "/absolute/policy.json", "sha256": "64-lowercase-hex-characters"},
    "application_capacity_calibration": {"path": "/absolute/app-capacity-calibration.tsv", "sha256": "64-lowercase-hex-characters"}
  },
  "process": {
    "executable_path": "/absolute/application",
    "application_tmpdir_path": "/absolute/application-tmp"
  },
  "storage": {
    "application_io_paths": ["/absolute/application-work", "/absolute/application-tmp"],
    "pressure_scratch_path": "/absolute/application-tmp",
    "output_minimum_free_bytes": 67108864
  },
  "schedule": {
    "seed": 731,
    "duration_seconds": 30,
    "sample_interval_ms": 250,
    "startup_deadline_seconds": 10,
    "total_deadline_seconds": 50,
    "term_deadline_seconds": 2,
    "kill_deadline_seconds": 2,
    "minimum_overlap_seconds": 20,
    "startup_ready_windows": 2,
    "cpu_duty_basis_points": 7000,
    "pressure_cpu_affinity": [2],
    "application_cpu_affinity": [2],
    "disk_bytes_per_second": 1048576,
    "scratch_file_bytes": 65536,
    "network_requests_per_second": 100,
    "network_payload_bytes": 256
  }
}
```

All input JSON is strict canonical UTF-8 JSON with sorted keys, compact
separators, a final newline, no duplicate keys and no non-finite numbers. Input
files are opened as bounded regular files with no-follow/nonblocking flags and
are rechecked for replacement or mutation while read. Paths must be normalized
absolute paths without symlink aliases.

Calibration is finite and records raw external measurements. It exercises the
same seeded CPU duty, block write rate and loopback request rate that the final
recipe will use. The calibration profile must match the final affinity,
interval and resource intensities; its calibration duration can be shorter.
The disk worker uses aligned `O_DIRECT` writes and one `fdatasync` per sample
window so its bounded writes reach the filesystem's block path rather than
remaining only in the page cache. Independent `/proc/diskstats` counters and
I/O PSI/queue evidence are still required; generator byte counts alone do not
qualify as block-device pressure. The result includes per-window CPU counters and CPU PSI, diskstats and I/O PSI,
`/proc/<worker>/io`, loopback interface counters, request counts and a bounded
latency histogram. It derives a numeric readiness proposal from measured
medians. A caller selects readiness limits from those measurements before
confirmation; those values describe whether the pressure was present and
observable. They are not application performance thresholds.

Build a pressure-contention calibration with:

```sh
setsid python3 scripts/application-pressure-driver.py calibrate \
  --request calibration-request.json \
  --output pressure-contention-calibration.json
```

`calibrate` accepts 3–120 seconds. It creates one fresh worker session for each
selected CPU, one block-I/O worker and one loopback worker. It writes a
canonical calibration file only after complete samples, measured block
queue/stall evidence, clean loopback counters and worker cleanup all pass.
On failure, the bounded fixture retains per-window block counter deltas,
direct-I/O/fdatasync measurements, worker `/proc/<pid>/io` deltas, exit and
signal records, and a base64-bounded raw stderr capture with its digest and
human-readable excerpt. The independent reader uses each recorded monotonic
interval as the rate denominator. It allows at most 1% lower-clock jitter
(with a 1 ms minimum tolerance) in adjacent scheduled windows while still
requiring contiguous bounds, complete sample count and measured readiness.
The frozen recipe also carries a conservative event-file budget computed from
the maximum serialized sample row for its CPU set and backing-chain identity.
It reserves 2 MiB in the event file for startup, failure, application-boundary
and cleanup records. A separate 2 MiB free-space reserve protects the final
run receipt. Freeze rejects schedules whose maximum sample rows plus terminal
records exceed the 512 MiB event cap; the supported 10,800-second, 100 ms
profile remains available with two or four pressure CPUs, while wider profiles
that cannot fit are rejected before pressure starts. Disk capacity is budgeted
from the block-rounded write count in every sample window.

The final freeze request points at that calibration file and supplies its raw
file SHA-256 separately from the app-byte-capacity calibration hash:

```json
{
  "pressure_calibration": {
    "path": "/absolute/pressure-contention-calibration.json",
    "sha256": "raw-file-sha256"
  },
  "readiness_thresholds": {
    "cpu_busy_min_basis_points": 5000,
    "disk_write_min_bytes_per_second": 400000,
    "disk_queue_or_stall_min_microseconds": 1,
    "loopback_requests_min_per_second": 40,
    "loopback_latency_p99_max_nanoseconds": 1000000,
    "loopback_tx_min_bytes_per_second": 20000,
    "loopback_rx_min_bytes_per_second": 20000
  }
}
```

Freeze a recipe without launching an application or pressure worker:

```sh
python3 scripts/application-pressure-driver.py freeze \
  --request pressure-request.json \
  --output frozen-pressure-recipe.json
```

The recipe captures kernel and boot identity, pressure and application CPU
affinity, each exact app I/O directory, the scratch directory, mount IDs,
filesystem types, block device and sysfs backing chain, plus the IPv4 route,
`lo` ifindex and network namespace inode. The app I/O paths and scratch path
must share one real non-tmpfs block mount and backing chain. The calibration,
freeze and run phases recheck free space against the frozen reserve. File
creation uses an exclusive name and a recorded inode; cleanup removes only
that same file.

`run` must be started as a dedicated session leader, for example by a process
supervisor using `start_new_session=True`. The driver creates its fresh output
directory before the application starts. Once the driver has measured the
frozen number of consecutive readiness windows, it creates
`pressure-ready.json`. The controller then starts the application with both
`ALLOCATBELT_APP_PRESSURE_NONCE` and the frozen `TMPDIR`, and atomically
publishes a canonical `launch-record.json` in that run directory. The record
contains the frozen recipe digest and nonce, actual PID and `/proc` start
ticks, executable path and raw hash, cwd, TMPDIR, CPU affinity and network
namespace inode. The driver independently checks those values against the
live process before accepting the binding.

```sh
setsid python3 scripts/application-pressure-driver.py run \
  --recipe frozen-pressure-recipe.json \
  --expected-recipe-sha256 RECIPE_SELF_DIGEST \
  --launch-record /absolute/run/launch-record.json \
  --output-dir /absolute/run \
  --ready-file /absolute/run/pressure-ready.json
```

The driver records canonical JSONL samples, the copied launch binding, a
process binding and a run receipt. Samples contain independently measured
per-CPU utilization and PSI; writes, queue depth, weighted block time and I/O
PSI on the frozen application device; `/proc/<worker>/io` deltas; and `lo`
bytes, packets, errors and drops. The loopback worker uses real IPv4 TCP
requests to `127.0.0.1`; the recipe claims shared-kernel loopback pressure only
and never claims a physical NIC. `run` exits unsuccessfully on missing or
sparse samples, failed readiness, early application exit, deadline breach,
storage reserve loss, worker error, scratch mismatch or incomplete cleanup.
It writes a failed run receipt when bounded artifacts can still be preserved.

One loopback worker owns both TCP endpoints and advances their nonblocking
I/O in a single thread. It preserves partial reads and writes, seeded payload
validation, `TCP_NODELAY`, request pacing and the worker ownership protocol.
Each exchange has an absolute two-second deadline. Its RTT starts before the
entire exchange helper and ends after the assembled client echo returns,
before payload validation; readiness waits and frame assembly remain inside
that interval. The 64-bucket histogram and readiness thresholds are unchanged.
This changes the generator's internal scheduling topology and requires fresh
source provenance for subsequent measurements.

The socket-state and timing tests can run without network access:

```sh
python3 -I -B scripts/test-application-pressure-loopback-pump.py
```

Every new driver run and calibration uses a durable three-step worker start
protocol. The parent first records and syncs the exact isolated worker PID,
`/proc` start ticks, PGID, session, role and nonce. A worker verifies that row
against its own identity and the parent PID/start, then acknowledges it while
remaining blocked. The parent syncs the exact acknowledgement set and a
pressure-start record before sending the separate work-start grant. Workers
install `PR_SET_PDEATHSIG` before opening load sources and exit if the bound
driver lifetime changes. The readiness marker includes the protocol name and
the ownership/acknowledgement journal hashes. The pressure reader accepts the
older pressure-start-only event form for archived records; SourceV5 soak
preflight requires the durable protocol and its independent reader checks all
three event records before accepting readiness.

For `calibrate`, the ownership, acknowledgement and work-start journals are
private temporary files beside the calibration output. They are synced before
the corresponding worker grants and removed only after a successful calibration
receipt is published. Failed calibrations retain them with the bounded failure
diagnostics. During a SourceV5 soak, the outer runner is a Linux child subreaper
before it launches the driver. It captures worker identities from the driver's
child list and, if the driver dies, from its adopted children; it preserves the
same start/session bindings through adoption and reaps only those exact child
PIDs. If an adopted zombie has lost its command line, its pressure role is
authenticated only by an exact PID/start/PGID/session/nonce match in the
durable ownership event. Other direct-child zombies are recorded as unknown
and reaped with `waitpid`; they never fill a missing worker role and make the
inventory fail. Unknown live children are never signalled.

The outer SourceV5 supervisor records TERM and HUP from before pressure-driver
`Popen` through readiness, application supervision, final driver wait and
cleanup. It restores the exact handlers it replaced after cleanup and writes
a bounded interruption receipt with the stable `128 + signal` exit code. A
missing or incomplete inventory after driver exit fails cleanup.

SourceV5 keeps pressure supervisor stdout/stderr logs beside the pressure
artifact directory. The artifact directory itself remains the validator's
exact five-file set.

The independent reader does not trust the receipt's pass label. Its caller
supplies the recipe self digest and raw digests for the run receipt, event
stream, launch record, process binding and readiness marker:

```sh
python3 scripts/application-pressure-readback.py verify \
  --recipe frozen-pressure-recipe.json \
  --expected-recipe-sha256 RECIPE_SELF_DIGEST \
  --artifacts /absolute/run \
  --expected-run-sha256 RUN_JSON_RAW_SHA256 \
  --expected-events-sha256 EVENTS_RAW_SHA256 \
  --expected-launch-sha256 LAUNCH_JSON_RAW_SHA256 \
  --expected-process-binding-sha256 PROCESS_BINDING_RAW_SHA256 \
  --expected-ready-sha256 READY_JSON_RAW_SHA256
```

It hashes and parses the canonical JSONL stream one bounded line at a time,
then checks exact schemas, raw artifact hashes, calibration measurements and
threshold derivation, sample cadence, counter arithmetic, readiness for every
complete application-overlap window, the minimum conservative overlap
interval, launch PID/start identity, and that every pressure worker session
has exited and been reaped. It retains one event at a time instead of copying
the full stream into line and event-object lists. It also confirms the
application PID/start pair is dead after its last live window and the scratch
inode is gone. Each event line is capped at 2 MiB, so streaming readback keeps
resident event data bounded independently of run duration. The raw receipt
hash and its internal self digest are
separate values: the CLI expects the raw JSON file SHA-256, while the recipe
and process-binding digests are canonical self digests over their bodies.

The driver caps an application pressure schedule at 12,000 seconds and 120,000
samples at the 100 ms minimum cadence. That finite horizon can cover a three
hour app soak plus its drain window in one continuous pressure session;
chunking or restarting pressure during that window is not supported. The
separate calibration remains capped at two minutes. Scratch files are at most
1 GiB, cumulative block writes are at most 64 GiB per schedule, loopback
traffic has fixed per-second and cumulative byte caps, events are capped at
512 MiB, and calibration files at 64 MiB. Startup, total, TERM and KILL bounds
are required numeric recipe fields. No command in this lane starts a
qualification campaign, benchmark decision, production token or soak run.

Controller integration is still required before any qualification use. This
lane does not yet bind trusted monotonic production/drain endpoints or prove
that application CPU affinity overlaps the controller's production interval.
Qualification must remain fail-closed until those externally authenticated
trace fields and affinity evidence are supplied and independently validated.
The synthetic Python sleeper in the native test exercises launch and readback
wiring only; it is not a real application, production/drain overlap,
performance result or soak qualification.
