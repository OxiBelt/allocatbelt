# Fuzzing

`heap_ops` feeds libFuzzer's inputs to `allocatbelt_core::model::run`, which
interprets them as programs of heap operations (allocations of every kind
and alignment, frees across two attached thread caches, a detached one and
the uncached API, in-place resizes, cache flushes and retirements, purges,
decay passes, clock and purge-delay changes, with randomized placement on
or off) against the checking mock `Os`. A panic is a heap bug.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly-2026-09-28 fuzz run heap_ops -- -max_total_time=600 -rss_limit_mb=4096 -max_len=4096
```

The unit tests run the same interpreter on random programs on stable
(`tests::fuzz_programs`).
