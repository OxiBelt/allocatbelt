# Application qualification tools

This unpublished, dependency-free workspace package computes deterministic
simultaneous intervals for paired application traces. It is an offline
preparation tool; its results do not establish application qualification.

Build `application-analyze` with:

```sh
cargo build --release --locked -p allocatbelt-qualification-tools
```

`scripts/application-campaign.py` validates the frozen specification, source
manifests, per-ID records and process receipts, then writes the versioned
`ABQST01` input stream. The binary takes input and new output paths:

```sh
application-analyze INPUT_STREAM OUTPUT_STREAM
```

The analyzer reads one independent pair group at a time. Each bootstrap draw
resamples paired processes and their contiguous original-ID blocks. Mixed
families share their actual process and block selections. Separate groups use
independent, versioned SplitMix64 streams with rejection-uniform indexing.
Resampled p99 uses the whole weighted pseudotrace. Suite endpoints reuse those
primary draws with the frozen rational profile/family/context weights; the
simultaneous critical value comes from the single packed draw matrix.

The decoder bounds frame sizes, cardinalities and declared vector storage,
rejects trailing data, and recomputes observed p99 before resampling. Output is
created exclusively with private permissions. The parent verifies source,
input, executable and output identities; echoed labels alone are insufficient.

For the full-size functional and cost probe, run this on a native development
host and keep its receipts in the private resources checkout:

```sh
python3 -B scripts/test-application-analyzer-full.py \
  --binary target/release/application-analyze
```

The probe uses varied dense traces, 36 pairs, 100,000 standalone and 400,000
mixed observations, 50,000 draws, and an independent small reference. It checks
analysis feasibility, not allocator speed. Campaign execution stays disabled
until actual runtime/policy readbacks and all prerequisite checks are wired.
See [the acceptance plan](../../docs/research/resource-runtime-plan.md).
