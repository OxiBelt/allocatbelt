# Prospective application campaign inputs

The campaign controller continues to accept archived SourceV4 manifests with
campaign-spec and campaign-plan V2. New `source-manifest` output uses
`allocatbelt.application-source-manifest.v5`; pass `--legacy-v4` only for the
existing functional-only fixture. V5 keeps the runtime readback validator as a
separate pin and adds the exact regular-file pins for the campaign controller,
feedback reader, byte-capacity producer, pressure driver and reader, soak
recipe builder and reader, and soak runner.

V5 also stores a numeric feedback policy artifact. Its version and sample
timing contract come from the pinned feedback reader and Rust policy module.
Its CPU, disk, and download control values are extracted from the Rust
application policy builder for each of the 15 workload/profile contexts. The
artifact records all contributing source paths and raw hashes and hashes its
canonical policy body. Validation with a live source root rebuilds the artifact
from those bytes, so a renamed policy label cannot stand in for numeric
configuration.

This artifact does not claim that feedback launch inputs are complete. The
collector Control charge, meter attachment counts, and fixed global Control
baseline still need a construction-only numeric emitter. Campaign-spec V3
reports that gap and keeps execution disabled until those values are derived.

Campaign-spec V3 requires SourceV5 inputs and a `qualification_inputs` object
with one capacity template and one pressure condition for every host and
workload/profile context. Capacity templates pin request and context files,
the calibration identity and calibrator, and either null evidence or pins for
the artifact, receipt, and campaign stage receipt. Null evidence keeps
`confirmation_ready` false even when rates and oracle references are present.

The evidence fields are references only in this phase. It checks supplied raw
file pins when a campaign-input directory is available, but it does not
validate the producer TSV, provenance, identity, or calibration receipt, and it
does not treat a claimed controller hash or timestamp as proof of campaign
chronology. A later validator must compare those artifacts with the actual
campaign ledger and establish calibration completion before confirmation.
Even when all evidence files and hashes are present, `capacity_evidence_ready`
and `confirmation_ready` remain false until those checks exist. Pressure
conditions bind the capacity key, condition bytes, pressure calibration
outputs, readiness thresholds, and prospective driver schedule.

Campaign-plan V3 freezes reusable capacity and fixed/pressure feedback
templates per host and context. The SourceV5 soak recipe derives a run nonce
from the selected template nonce, campaign job, `soak` member, and ordinal. The
plan still contains no live process IDs and claims no observed proof. The
pressure-first soak runner waits for measured readiness before application
`Popen`, then atomically binds the actual process identity for the pressure
driver.

The SourceV5 soak contract and its independent v2 composite are documented in
[`application-soak-readback.md`](application-soak-readback.md). Runtime and
pressure qualification remain disabled while capacity chronology and
construction-derived feedback composition are incomplete. Raw pins and a
successful pressure startup marker do not complete those semantic gates.

The V3 plan also pins the regular-inventory SHA-256 of
`application-campaign-inputs.py`. Validation, freezing, and plan verification
re-read and hash that exact module before compiling it; a changed helper fails
before its code can execute.
