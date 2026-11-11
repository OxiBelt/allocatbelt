# allocatbelt with Tokio

`crates/allocatbelt-tokio` is a separate crate of this workspace (not published, `publish = false`) that connects a Tokio runtime's threads to allocatbelt through Tokio's stable runtime hooks. The allocator itself depends on no executor; nothing here changes it unless the hooks are installed.

**Performance not measured; benchmark gate intentionally disabled.** The hooks change where memory is cached; whether that makes a workload faster is not measured.

```rust
#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

let mut builder = tokio::runtime::Builder::new_multi_thread();
allocatbelt_tokio::Hooks::new().install(&mut builder);
let runtime = builder.build()?;
```

| Hook | Tokio callback | What it does | Setting |
|---|---|---|---|
| Park | `on_thread_park` (stable) | the parking thread hands its cache back (`Allocatbelt::flush_thread_cache`): bounded, allocation-free | `Hooks::flush_on_park` (on) |
| Start | `on_thread_start` (stable) | the thread takes the next shard (`Allocatbelt::set_thread_shard`), from `first_shard` on; Tokio also runs it for blocking-pool threads | `Hooks::shard_per_thread` (on), `Hooks::first_shard` (0) |

Tokio keeps one callback per hook: `install` replaces the builder's start and park callbacks. An application with its own calls `Hooks::thread_started` and `Hooks::thread_parking` from them.

## What it does not do

It does not change Tokio's scheduling: which task runs, on which worker, in which order, and when a task yields are Tokio's decisions (and the application's, with `yield_now` or `spawn_blocking`). The task hooks that could observe polls (`on_before_task_poll` and the others) need `--cfg tokio_unstable` and are not used.

## Regions in tasks

A task can own a `Region` and keep its pieces across `.await`s; the future stays `Send` because the region moves with it, so `tokio::spawn` accepts it on the multi-thread runtime. Keeping a `&Region` itself across an `.await` is refused at compile time (a region is not `Sync`). The crate's documentation has both as tests; reset the region when a unit of work ends ([region.md](region.md)).

## Tests

`crates/allocatbelt-tokio/tests/hooks.rs`, with allocatbelt as the global allocator: parking workers hold no cached block right after the hook (and do hold some without it); started threads take consecutive shards, wrapping at 64; `install` runs on a real runtime; tasks keep region pieces across awaits while moving between workers. The core test `preferred_shards_replace_the_attached_one` checks the shard preference in the heap.
