# SourceV5 mixed external-pressure soak

The parent soak reader keeps archived
`allocatbelt.application-soak-parent-recipe.v1` and
`allocatbelt.runtime-soak.v1` fixed-policy records on their original validator
path. SourceV5 uses parent recipe v2 and the Rust `runtime-soak.v2` receipt for
the original mixed external-pressure soak job.

A v2 parent recipe is prospective. It binds the full captured SourceV5 campaign
controller, the campaign spec and plan raw and semantic digests, one exact
capacity template, one pressure condition and its calibration pins, the
SourceV5 feedback process template, the compiled app construction-only probe,
the timed `soak_artifacts.allocatbelt` binary, the external oracle ring, and the
readers and runner. The construction probe comes from
`artifacts.allocatbelt`; it is re-run with
`--emit-feedback-policy-only --workload mixed --profile PROFILE` and compared
byte for byte with its pinned output. This keeps the app emitter distinct from
the timed soak binary.

The per-run nonce is instantiated from the plan's reusable feedback-template
nonce and the campaign ID, job run ID, `soak` member, and planned ordinal. No
process ID or run proof appears in the prospective recipe. The trace identity
uses the timed soak binary and the runtime feedback executor label
`allocatbelt`; the Rust soak identity uses executor `bounded`. The validator
checks that mapping explicitly.

Before it starts the pressure driver, the runner establishes Linux child
subreaper status. It launches the pinned driver as an isolated session leader
and waits within the frozen startup deadline for its measured readiness
marker. The driver writes and `fsync`s an exact worker PID/start/PGID/session,
role and nonce ownership journal before it grants ownership to any worker.
Each worker installs a parent-death signal, verifies its parent PID/start
identity, and acknowledges that ownership row. The driver then writes and
`fsync`s the exact acknowledgement set and a separate pressure-start journal
before sending the work-start grant. Workers cannot begin pressure before that
last grant. The readiness marker binds the ownership and acknowledgement
journals by digest; SourceV5 preflight requires this strong marker and the
independent pressure reader verifies the matching event prefix.

The runner records each isolated worker's pinned command and process identity
while the driver is alive. If the driver exits first, the subreaper adopts its
children; the runner confirms the same PID/start/PGID/session identities across
that transition and reaps only those exact adopted children. When an adopted
worker has exited before the first process scan, the runner authenticates its
role from the durable ownership event's exact PID/start/PGID/session/nonce
row. Other adopted zombies are recorded as unknown and reaped as direct
children; they never count toward a worker role and make the inventory
ineligible. Unknown live children are never signalled. On abort the runner
gives the driver its frozen TERM/KILL cleanup budgets, then uses pidfd
signaling for any positively captured worker still alive. An empty or
incomplete worker set after driver exit is a cleanup failure, not evidence
that no worker escaped.

The outer supervisor records TERM and HUP beginning before pressure-driver
`Popen` and through readiness, application supervision, final driver wait and
cleanup. It restores the exact prior handlers afterward and writes a bounded
interruption receipt with a stable `128 + signal` exit code.
Only after the measured marker and complete worker inventory pass does the
runner start the soak process. Immediately after `Popen`, it records the actual PID and
`/proc` start ticks, executable digest, cwd, TMPDIR, CPU affinity, and network
namespace, then atomically publishes the pressure driver's authenticated
launch record. The app wall timeout begins before `Popen` and includes the
identity-binding callback. For a requested trace duration `D`, the frozen app
wall bound is `120s setup + D + 5s trace overrun + 5s drain + 60s shutdown +
60s postprocess`. The pressure sampling duration is derived as the driver's
startup deadline plus that app bound plus one second for the next 100 ms sample
to observe app exit. Thus the 10,800-second original soak uses an 11,050-second
app bound and an 11,061-second pressure window; the driver's total deadline
also covers its frozen TERM/KILL cleanup bounds. The immutable caller request
bytes and calibration fields stay pinned separately from the derived run
schedule and its semantic condition digest.

The pressure driver's stdout/stderr supervision logs are siblings of the
canonical pressure artifact directory. That directory remains the exact
five-file set consumed by the captured pressure validator.

The outer v2 composite has exactly these fields:

```text
schema, validated, passed, qualification_eligible, mode, identity,
source_manifest_sha256, source_tree_sha256, build_sha256,
candidate_binary_sha256, resource_ceiling_sha256,
fixed_global_control_baseline, receipt_sha256, validator_sha256,
monotonic_endpoints
```

Its identity is the exact 13-field external-soak identity. The five monotonic
phase endpoints (`started`, `trace_ended`, `drain_ended`, `shutdown_ended`, and
`postprocess_ended`) each carry a lower and upper bound. The reader verifies
the lower-endpoint scalar, chronology and bounded phase durations. It also
reuses the terminal-ID/checksum, 100 ms sample cadence, first/final 36,000-row
RSS windows, upper-median five-percent growth bound, hard resource ceilings,
scope limits, byte-credit bounds, reservation caps, final zero charges,
and fixed global Control-baseline checks. CPU, disk and download controls may
move within the construction-probe policy bounds; the separate feedback v3
reader reconstructs their complete transitions from the feedback trace.

Available byte credits are bounded by the current burst. Retained bytes are
bounded by the number of live reservation owners times the construction burst
ceiling, with at least one byte per owner. Tokens may refill while earlier
owners remain live, so retained bytes and available tokens have separate bounds.

`qualification_eligible` describes only this independently audited soak
component. A full feedback qualification also requires the separate pressure
readback and feedback v3 receipts; this composite does not recursively
validate either proof. The feedback reader consumes the exact soak receipt and
this composite by raw SHA-256, then validates its external-pressure proof and
trace independently. The campaign controller must require all three
independent results before applying any full qualification gate.

SourceV5 spec references use each manifest's internal semantic digest. The
selected parent recipe separately pins the exact raw manifest file SHA; the
reader checks both roles and runs the selected inventory-pinned controller's
full manifest verifier over the complete frozen host matrix before plan validation.
The v2 composite remains exactly 15 fields. The postflight artifact is checked
as a separate input-stability record and its digest is not appended to that
composite.

SourceV5 recipes remain launch-disabled when capacity evidence is missing or
only hash-pinned, when campaign chronology has not been independently checked,
or when construction-derived feedback composition is incomplete. Those states
are re-derived through the captured full controller on each preflight. The
current SourceV5 source keeps them false until the semantic evidence and
composition validators are available.
## Additive prospective resource budget

New bounded Soak work uses a caller-frozen
`allocatbelt.application-source5-soak-resource-budget.v2` document pinned by
raw and semantic SHA-256 in `materials-index.v2`. The document binds the exact
original job, SourceV5 manifest/tree, recipe/build receipt, prepared host,
observed host, and captured FixedR8/Soak source modules. It freezes the
original output, application TMPDIR, pressure scratch and fresh probe-capture
roots, full owner deadlines, the exact 10,800-second/108,001-row APP schedule,
per-domain byte/inode ceilings, origin-device free-space floors, durable
receipt reserves, monitor stream bounds and every writable artifact limit,
including distinct launch-authorization, component, failure, and pressure-
readback roles. It derives the output inode catalogue from the exact bounded
direct-file set and five pressure children. It cannot be inferred
from post-run usage. Omitting the budget keeps the archived
`materials-index.v1`, component, receipt, and blocker behavior intact.

Before any probe, pressure or APP owner starts, the bounded adapter validates
the exact material/helper/job bindings and checks existing usage and remaining
free-space/reserve against the prospective ceilings. The resource monitor
streams canonical, hash-chained usage rows across preflight, construction
probe, pressure startup, APP lifetime, pressure cleanup and Source5 postflight.
The v3 launch receipt seals the exact monitor prefix at APP return; the final
component and host receipt bind the complete stream. Its
cadence and maximum gap are caller-frozen safety bounds checked against the
existing owner polling and complete wall deadlines; they do not change the
APP's original 100 ms cadence or its 108,001-sample qualification contract.
Nested storage roots count once toward aggregate filesystem allowance while
retaining their individual caps.

The selected-floor ProbeV2 capture receives the resource callback through the
SourceV5-pinned Composer into the existing FixedR8 owned-process monitor. That
callback is combined with FixedR8's existing TMPDIR checker, so either bound
can request the owner's status-125 stop and cleanup. The Soak resource monitor
does not create or signal a PID. Budgeted ProbeV1 captures use the same owner
callback composition while preserving their historical argv/environment
shape. Both capture paths retain the actual owner result before post-return
validation.

Bounded preparation keeps the same monitor instance from its first resource
sample through ProbeV2 setup and the Soak supervisor. Probe construction setup
continues sampling in the preflight phase; the phase advances to
`probe_capture` at the existing owner prelaunch callback and advances to
`preflight_audit` after that owner returns. The adapter carries that monitor
through Source5 postflight and requires the same closed, budget-pinned monitor
when it writes the bounded host receipt. A returned lifecycle failure remains
an unvalidated component with `passed: false`.

Bounded component replay uses an additive component schema and host
verification v3 receipt containing the prospective budget pin, monitor stream
and high-water recomputed as the maximum of sampled and quiescent final usage.
The bounded result sets `bounded_execution_ready` only after strict live and
offline replay pass. It keeps `qualification_eligible` and global
`execution_ready` false. Offline
replay checks the complete identity-only evidence map and exact recursive
writable-tree membership, replays the ProbeV2 capture through the captured
Composer, binds monitor phases to captured probe/APP/pressure owner intervals,
checks stable origin root identities across all rows, recomputes final usage,
and reruns the original Soak and pressure validators. Historical budgetless
receipts continue to report
`prospective_bounded_soak_resource_budget_not_pinned`; a functional fixture or
short native owner run cannot establish the original three-hour qualification
horizon.

The Soak adapter and the single-APP pressure reader provide additive
material-index v2, component v2, host-receipt v3, and host-v3 replay contracts.
The controller must pin the caller-supplied raw/semantic budget before
helper-input creation; chronology must index the monitor, owner-result,
writable-tree, component, and host-receipt paths before nested reads; and the
dispatcher must compare the complete bounded result with the original journal
ancestry. Those cross-module caller changes are a companion integration patch
and are required before the full-host bounded path is end-to-end. The
host-receipt pin stays alongside the component in job evidence because
embedding it in the component would create a digest cycle. The captured
Composer's keyword-only `resource_monitor` is required for ProbeV2; the default
`None` call and historical ProbeV1 argv/environment stay unchanged.

The bounded offline API returns the exact schema
`allocatbelt.application-source5-soak-bounded-offline-result.v1` with
`{schema,campaign_id,host_id,run_id,component_sha256,host_verification,
resource_budget,resource_monitor,final_usage,readback_sha256,validated,passed,
bounded_execution_ready,qualification_eligible,execution_ready}`. It reports
bounded readiness only after all live and offline evidence passes. It leaves
qualification and campaign execution readiness false. This candidate contains
no three-hour host capture or SourceV5 re-preparation evidence.

## Authenticated captured-output replay

The additive
`verify_source5_soak_component_captured_outputs(..., captured_evidence=...)`
entrypoint consumes Root's authenticated
`allocatbelt.application-source5-archived-job-read-view.v1` for the exact
original Soak job. It verifies the request, final checkpoint and signed object
manifest again against the original campaign/job pins before it reads staged
output objects. The older `verify_source5_soak_component_offline` API retains
its closed identity-path-map schema and behavior.

Captured object lookup keys remain the original absolute paths. The replay
opens only the exact local stage files supplied by the authenticated view,
checks their no-follow regular-file identity, owner, mode, single-link status,
size and raw digest, and streams large terminal, sample, monitor and pressure
records. It never stats a reclaimed origin path or fabricates origin
filesystem metadata. SourceV5, SpecV3, PlanV3, binaries, capacity inputs and
other retained dependencies continue through their real pinned paths.

ProbeV2's nonempty-capable `opaque_trace` TMPDIR is accepted only with the
request's exact typed tree row, the raw-pinned
`allocatbelt.application-feedback-probe-tmpdir-inventory.v1` document and the
ProbeV2 capture receipt that binds the same initial/final root identity and
inventory pin. The row's file descendants must match the signed archive
objects one-to-one; directory facts come only from the receipt-backed typed
inventory. An empty directory is never inferred from a missing archive file.
The verifier preserves the original policy, host receipt, resource-monitor,
single-APP pressure, 100 ms sample, 108,001-row, RSS-growth and final-usage
checks. Short functional diagnostics can validate lifecycle wiring but do not
qualify the three-hour run.
