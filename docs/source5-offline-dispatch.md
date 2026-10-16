# Source5 offline component replay

The exact source cohort follows the frozen SpecV3 qualification profile:
`two_kvm_hosts_v1` requires two KVM hosts, while an absent selector retains
the legacy three-host matrix. Replay must verify every selected host; it
cannot drop a host from an already frozen generation.

The Source5 offline dispatcher accepts one closed host-journal request, its
captured identity-mapped evidence store, and an exact original job-record pin.
Before loading the captured chronology or component modules, it checks the
complete three-host `Source.files` inventory and every declared build,
analysis, Soak, and domain-calibration artifact against the exact typed index
roles and raw bytes. A terminal source symlink is represented only by its
literal UTF-8 target bytes under `typed_source_symlink`; its target must be an
indexed regular source file. Symlink rows are never opened, mapped as files,
or loaded as modules. A missing or incorrectly typed row fails closed. It
then replays the byte-only journal/index/receipt contract, then selects the
unique authorization, terminal, job record, and strict component receipt for
that job. Fixed-pair evidence is routed through the existing fixed-pair
offline verifier. Pressure evidence requires a typed journal context, proves
the original historical registration and authorization, replays the exact
successful confirmation predecessor, and then replays both ordered normal
APP members through the existing pressure, ProbeV2, feedback, output, process
ledger, and finalization validators.

Every path-based component read is bound to a role-indexed captured file and
an identity map. The dispatcher validates bounded store metadata and closes
the external index and complete typed Source.files/artifact roles before
consuming nested streams, then checks raw captured bytes and local file
identity around the readers. It rejects missing or untyped files. The pressure
parser also closes the same source roles from direct captured metadata before
hashing nested source/artifact streams or compiling its typed dispatcher. It
treats arbitrary `.json` payload files as opaque unless an exact versioned
schema pin names them. It compiles selected source modules only from source
bytes whose typed inventory and execution-manifest pins match. The adapter has finite entry,
per-role byte, and path-map bounds; it retains the independent journal-role
ceiling and does not add a whole-host aggregate byte ceiling. It does not
accept success flags or caller-provided module objects.

The direct pressure API also checks each mapped regular local file's raw digest
and byte count against its closed captured/index row, including component
recipes, readbacks, host receipts, specs, plans, and streams. This pass follows
the complete role-metadata closure and precedes component JSON parsing or
captured module loading; file descriptors and saved `lstat` identities remain
part of the check.

Component replay results keep `qualification_eligible` and `execution_ready`
false. Structural journal claims remain claims until the selected component
has been recomputed, and the complete three-host numeric cohort still requires
its separate original analysis replay. The strict Source5 Soak verifier still
returns its exact bounded-resource-budget blocker after replay because no
prospective bounded-Soak budget is pinned; the dispatcher preserves that
blocker. Both pressure calibration checks use the strict offline scope reader
with the original SourceRoot and closed identity map. The five-argument pressure offline API
continues to fail closed; the additional `source5_journal_context` must carry
the exact host request/store/job-record tuple.

For a prospectively selected capacity-floor policy, the normal external-pressure
pair adapter adds `ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID` to each APP's
allowlisted environment only after the SourceV5 campaign selector, source-pinned
floor descriptor, validated three-file capacity bundle, shared policy context,
and that member's resolved-policy identity agree. Exact environment replay
propagates the selector across bounded/Tokio and allocator comparisons; the
fixed-policy adapter keeps its original environment without this selector.
Missing, unknown, or mismatched bindings fail during preflight, before an APP
launch.

The native fixture entry point is
`replay_genuine_job_fixture(request, captured_evidence, job_record_pin)` in
`test-application-source5-offline-dispatch.py`. It is intended to consume a
real original capture. A synthetic record or stored boolean is not a positive
replay witness. Root/Sol review and native replay are required before any
qualification claim; this candidate has no positive native replay result.
