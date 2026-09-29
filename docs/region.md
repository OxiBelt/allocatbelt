# Regions: explicit-lifetime allocation

`allocatbelt::Region` is an opt-in API for many values that die together, such as the temporary data of one request or task. It takes *chunks* from the allocatbelt heap, hands out consecutive pieces of them (bump allocation), and frees them all at once when it is reset or dropped. It was added by Stage E of the theory-driven plan.

**Performance not measured; benchmark gate intentionally disabled.** Nothing here claims that a region is faster than the global allocator for any workload.

Nothing is ever placed in a region implicitly: the global allocator does not look at sizes, threads or workloads to decide that, and ordinary allocations keep their lifetime and free semantics. A program that never names `Region` is unaffected. It works whatever the process's global allocator is; the chunks always come from the allocatbelt heap.

## Using it

```rust
use allocatbelt::{Region, RegionError, RegionOptions};

fn run() -> Result<(), RegionError> {
    let mut region = Region::with_options(
        RegionOptions::new()
            .with_chunk_size(16 << 10)   // standard chunks of 16 KiB
            .with_retain_bytes(64 << 10) // a reset keeps up to 64 KiB of them
            .with_limit_bytes(1 << 20),  // at most 1 MiB of chunks at once
    );
    for request in ["GET /a", "POST /b"] {
        let len = region.scope(|r| {
            let method = r.alloc_str(request.split(' ').next().unwrap_or(""))?;
            let scratch = r.alloc_slice_fill(256, 0u32)?;
            scratch[0] = method.len() as u32;
            Ok::<_, RegionError>(scratch[0])
        })?;
        assert!(len > 0);
    }
    Ok(())
}
```

`crates/allocatbelt/examples/region_request.rs` is a longer example: four worker threads, each owning a region, parse made-up requests into it and reset it after each one (`cargo run --release -p allocatbelt --example region_request`). It is not an OxiBelt integration and says nothing about OxiBelt's behaviour.

| Method | What it does |
|---|---|
| `alloc_copy(value)` | one `Copy` value |
| `alloc_slice_fill(len, value)`, `alloc_slice_copy(&[T])` | a slice of `Copy` values |
| `alloc_zeroed_bytes(len)`, `alloc_str(&str)` | bytes and strings |
| `reset()` (`&mut self`) | forgets every piece; keeps standard chunks up to the retain bytes |
| `release()` (`&mut self`) | forgets every piece and returns every chunk |
| `scope(f)` (`&mut self`) | runs `f` with `&Region`, then resets |
| `stats()` | chunks, chunks of their own, capacity, bytes used, resets |

Every allocation returns `Result<&mut _, RegionError>`: `Layout` (size overflow, over `isize::MAX`, or alignment above the heap's 4 MiB), `Limit` (a new chunk would pass the limit) or `OutOfMemory` (the heap refused a chunk). A failed request leaves the region and its other pieces unchanged.

## Safety rules

The API has no `unsafe` for its users; the compiler enforces these, and the `compile_fail` doctests on `Region` check them:

- **Pieces borrow the region.** Allocation takes `&self`, so any number of pieces are live at once; `reset`, `release` and `scope` take `&mut self`, and dropping takes ownership, so no piece survives any of them. A piece cannot leave `scope`.
- **Only `Copy` types, always initialized.** A type with a destructor is rejected (the region runs none), and every piece is written before a reference to it exists. There is no API that returns uninitialized memory or a raw pointer.
- **`Send`, not `Sync`.** A region owns its chunks, so a thread or task may own it and move it to another thread. Its bump state is in `Cell`s, so it cannot be shared between threads. It holds no thread-local state; an async task that keeps a piece across an `.await` borrows the region across it, which the compiler checks like any other borrow.
- **Metadata apart from payload.** Chunk descriptors are in a `Vec` owned by the region, never inside a chunk, so writing past a piece cannot corrupt the region's own state.

## Chunks and the reset policy

| Rule | Value |
|---|---|
| Standard chunk size | 64 KiB by default; `with_chunk_size` clamps to 256 bytes..=4 MiB and rounds up to 16 bytes |
| Chunk alignment | 16 bytes for standard chunks |
| Request that does not fit an empty standard chunk (size plus the padding its alignment may need) | a chunk of its own, exactly its size (rounded to 16) and alignment |
| Request that does not fit the rest of the current chunk | the next standard chunk (a retained one first); the rest of the current chunk stays unused until the reset |
| Reset | keeps the first standard chunks, in the order taken, while their total stays within the retain bytes (1 MiB by default; 0 keeps none); returns every other chunk, and every chunk of its own |
| Release, drop | returns every chunk |
| Limit | bytes of chunks held at once (no limit by default) |

Chunks of their own are never kept, so one unusually large request does not stay resident after the reset. Reset and release cost one step per chunk held; no value is dropped, since only `Copy` values are held. `stats().used` counts bytes handed out since the last reset, alignment padding and skipped chunk tails included.

A long-lived region that keeps allocating never reuses memory until it is reset: give it a limit, or reset it at the end of each unit of work.

## Differences from the global allocator

These are deliberate, and the hardening of global allocations is unchanged:

- **No per-piece randomization.** Pieces are consecutive in a chunk, in allocation order.
- **No double-free detection.** Pieces are never freed one by one, so there is nothing to detect.
- **Guard pages only between segments.** A piece that overflows runs into the next piece of the same region, not into a guard page. Chunks are ordinary heap blocks, so the heap's segment guard pages and out-of-band metadata still separate the region from other memory; a chunk too large for a page run is a huge block of whole segments.
- **Memory is reused only after a reset**, not piece by piece.

## Where the code is

| Part | File |
|---|---|
| Arithmetic: `align_up`, `bump`, chunk sizing, `fits_standard`, `own_chunk`, the retention rule, the limit; checked, returns `None` instead of wrapping; `forbid(unsafe_code)`, `no_std` | `crates/allocatbelt/src/core/region.rs` |
| Chunks, pointers and the public API | `crates/allocatbelt/src/region.rs` ([unsafe-boundary.md](unsafe-boundary.md) lists its sites) |
| Tests | `core/region/tests.rs` (arithmetic, property tests), `region/tests.rs` (over the system allocator, run under Miri in CI), `tests/region.rs` (heap-backed), `compile_fail` doctests on `Region` |
