# Shared host campaign chronology journal

This module adds a private, per-campaign/per-host transaction journal around
the existing SourceV5 capacity stage and one original fixed-confirmation pair
runner. It leaves the original SpecV3, PlanV3, fixed policy recipes, run IDs,
member descriptors, and the R15 capacity-completion schema unchanged.

The journal is deliberately narrower than campaign readiness. It can establish
the order of successful calls made through these locked APIs and record the
actual direct pair-runner process that they launched. It cannot establish that
all work on the host used these APIs, cannot reinterpret the controller's
existing post-run ledger as pre-launch evidence, and does not make a campaign
execution-ready or qualification-eligible. Pressure dispatch and aggregate
fixed/pressure composition are unsupported here.

## Locked API

The module is `scripts/application-campaign-chronology.py`. Its SourceV5
manifest must contain that path as one regular file inventory entry for every
host. It is separately recorded as `chronology_module`; it is not added to the
existing `qualification_harness` key set.

Create a mode-0700 output root outside SourceV5 and acquire the named lock with
`campaign_host_lock(output_root, campaign_id, host_id)`. The context holds an
owned regular mode-0600 `O_NOFOLLOW` lock file and an exclusive `flock` for the
entire API call. Every caller for one campaign/host must use that same exact
output root to share the lock file. Locked APIs require the module-issued live
fd token and verify its descriptor identity; a caller-supplied boolean does not
represent lock ownership.

The stage and registration calls are:

```python
with campaign_host_lock(output_root, campaign_id, host_id) as lock:
    stage = run_capacity_stage_locked(
        lock, plan_pin, spec_pin, source_root, input_root, host_id,
        observed_host_pin, output_root,
    )
    registered = register_capacity_completion_locked(
        lock, plan_pin, spec_pin, source_root, input_root, host_id,
        observed_host_pin, output_root, stage["completion"],
    )
```

`run_capacity_stage_locked` invokes the exact captured R15 SourceV5 module and
keeps its 15-context run under the campaign/host lock. Registration calls the
captured `verify_capacity_completion` API, which replays all 15 entries and
their bundles before sealing the registration event. Both records bind the
original raw and semantic spec/plan pins, the complete selected SourceV5 manifest cohort,
host controls, boot identity, chronology/stage/controller/input/reader/producer
module pins, the original schedule digest, and the completion, sealed ledger,
and terminal-head pins. Registration must precede creation of the original
confirmation host directory and any dispatch authorization. A prior directory,
prior controller ledger, missing locked stage event, or conflicting
registration blocks progress.

`authorize_dispatch_locked` accepts one exact original PlanV3
`confirmation`/`fixed_policy` job for the selected host. It rebuilds the
original pair members with the captured controller's runtime-binding and
runner-argv functions, checks their recipes against the frozen plan, and
rejects pressure jobs. Open-loop jobs also require the original pinned oracle
files. It replays the capacity completion before appending and fsyncing a
unique authorization record. The returned one-use token can only be consumed
by `launch_authorized_locked` while that same fd lock remains held.

The launcher rechecks source, host, capacity, registration, and job pins before
direct `subprocess.Popen` of the exact SourceV5 `run-application-pair.sh` path
with `shell=False`. It writes and fsyncs `dispatch_authorized` before that
Popen, then keeps the lock through live PID/start-time/executable/cwd/affinity/
network-namespace/environment observation and a fsynced `dispatch_bound`
record. The process role is `campaign_pair_runner`: this is the shell runner's
PID, not either application member's PID. Both original member recipes and
report nonces remain in the immutable authorization. Terminal records keep
the direct leader's `process_reap_status` (`not_started`, `owned_reaped`,
`not_reaped`, or `unverified`), the matching `process_reaped` boolean and
`return_code`, and the separate typed `process_group_cleanup_status`
(`not_started`, `clean`, `unclean`, or `unverified`). `process_reaped` is true
only for a positively observed owned reap, represented by
`process_reap_status: "owned_reaped"` and an integer `return_code`. A
`not_started` process has false `process_reaped` and a null `return_code`;
`not_reaped` and `unverified` likewise require false and null. Every unsafe
cleanup carries an error digest. Timeout and interruption records retain their
trigger even if cleanup also fails, and their API result reports
`cleanup_failed` with the original dispatch status. The launcher requires
default `SIGCHLD` ownership and `waitid(WNOWAIT)` at every leader observation:
it observes exit without reaping, checks members of the fresh session while
the leader still anchors its process-group ID, rechecks default disposition
and unreaped ownership after each procfs scan immediately before a numeric
group signal, sends bounded TERM/KILL cleanup, clears the active
signal-process reference, and only then attempts one bounded final reap. The
bounded wait is attempted only while default `SIGCHLD` and unreaped-child
ownership remain verifiable. If ownership is lost or the disposition is
unsupported, the journal records `unverified`, false `process_reaped`, and a
null `return_code`; it does not call `Popen.wait` or signal a numeric PGID.
The launcher performs no numeric process-group operation after a positive
reap. Signal handlers only record the requested signal; cleanup and group
signaling stay in the owning launch path. The runner environment rejects
ambient Bash startup, option, and exported-function import controls such as
`BASH_ENV` before an
authorization can be journaled, so unpinned shell startup files cannot run
ahead of the SourceV5-pinned runner. Every authorization consumes its original
run ID; failed jobs are retained and cannot be retried under that ID.
Any terminal whose leader was not reaped or whose process-group cleanup is
unclean or unverified sets `cleanup_blocked` during journal replay and rejects
all later dispatch authorizations for that campaign/host. A scan failure uses
one bounded emergency SIGKILL and reap attempt while the unreaped leader still
anchors its group; the result remains unverified even if that fallback reaps
the leader. That numeric signal fallback independently requires default
`SIGCHLD` disposition and `waitid(WNOWAIT)` before observing or signaling the
leader. If those semantics are unavailable, it performs no wait and no numeric
signal, and records the reap status as `unverified`.

`verify_campaign_chronology_locked` replays the complete canonical JSONL
hashchain, validates each exact transition and process/exit binding, then
re-runs the full capacity completion verifier. Its result uses schema
`allocatbelt.application-campaign-chronology.v2`. `api_transaction_order_proven`
means only that the recorded operations were ordered through this module. The
result always keeps `qualification_eligible`, `execution_ready`, and
`controller_chronology_proven` false. `cleanup_blocked` reports unresolved
process ownership, not campaign readiness. `terminal_process_cleanup` returns
the per-dispatch reap status, matching boolean and return code, group-cleanup
status, and optional error digest. Journal replay rejects contradictory
combinations, including an `owned_reaped` status without an integer wait code.
A pending authorization or any
failed, interrupted, signaled, or timed-out pair remains visible in the
journal and is not a successful dispatch receipt.

## CLI

All commands require raw pins for the original plan, spec, and observed host
context. `run` holds the lock around the full R15 stage; `register` seals the
verified completion; `launch` authorizes and directly launches one original
fixed pair; `verify` replays the journal and capacity bundles. Separate CLI
invocations reacquire the same exclusive lock file. For example:

```sh
python3 -B scripts/application-campaign-chronology.py run \
  --plan INPUT/campaign-plan.json --plan-sha256 PLAN_RAW_SHA256 \
  --spec INPUT/campaign-spec.json --spec-sha256 SPEC_RAW_SHA256 \
  --source-root SOURCE --input-root INPUT --host-id host-1 \
  --observed-host INPUT/observed-host.json \
  --observed-host-sha256 HOST_RAW_SHA256 --output-root OUTPUT
```

Use the returned `completion.path` and `completion.sha256` with `register`,
`launch`, and `verify`. `launch` additionally takes `--job-run-id` and
`--pair-runner SOURCE/scripts/run-application-pair.sh`; open-loop launch also
requires `--campaign-artifacts-root`. Each command has a finite lock-acquisition
timeout. The existing controller does not call these APIs yet, so a journal is
evidence of its own transactions only; it is not evidence that the unchanged
controller dispatched every scheduled confirmation job.

## Verification witness

`scripts/test-application-campaign-chronology.py` builds bounded fake
application binaries and a three-host synthetic SourceV5 fixture. That fixture
pins its test-only pair-runner bytes in the regular file inventory and in
`spec.runner_sha256`; it retains the PlanV3 job matrix and run IDs, then
rebuilds source-bound template nonces and runtime recipes against the synthetic
source pins. That fixture is never eligible for qualification. On the native
x86_64/Rust 1.99.0 host the test suite exercises the actual chronology CLI
through the full 15-context capacity stage and replay, registration,
source-pinned synthetic-runner Popen, Popen-fsync ordering, private-lock
contention, prior-directory and missing-registration rejection,
output-collision consumption, source/boot drift, pressure rejection,
process-role and interpreter identity, BASH_ENV rejection before
authorization/Popen, SIGCHLD ignore/custom rejection before authorization,
post-Popen SIGCHLD-ignore fallback without a group signal, a live runner's
SIGCHLD disposition changing during procfs inspection without a later group
signal or reap, normal/signal/timeout cleanup with an escaped same-session
member, injected member-scan failure with the default-SIGCHLD emergency reap,
prevention of later authorization after
unsafe cleanup, descendant-held output cleanup after early runner exit, no
process-group operation after leader reap, exact reap-status/return-code replay
validation, and journal tamper rejection. The
synthetic runner records its own PID and original run ID, then
exits, waits on a bounded test flag, or leaves test-only descendants in its
owned process group or another group in the same session; it does not launch
an application. These sentences describe test coverage, not a completed native
pass. Native correctness evidence is recorded separately with the exact source
pins, logs, and exit status; an earlier failed attempt is not promoted by a
later source revision. A separate signed-e4e64 run confirms the unchanged
runner keeps its hard-disabled timing gate with these fake binaries. None of
the fake children or the synthetic fixture constitutes a campaign run,
calibration, or performance measurement.
