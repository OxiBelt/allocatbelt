# Class-to-segment candidate index: bounded design (Stage D3)

Design of the third part of Stage D of the theory-driven plan (brief section 7, D3), delivered as a design, which the brief accepts as an intermediate delivery next to D1 and D2. **Nothing in this document is implemented.** It records what the index would be, what it would cost, how it would stay correct, and what would justify building it.

**Performance not measured; benchmark gate intentionally disabled.** No benchmark was run, and no claim below is a measured speed-up.

## 1. What discovery work is left after D1 and D2

Two levels of summaries already avoid scanning blocks and pages: a page's *summary* word (bitmap words that may hold free blocks) and a segment's per-class *availability* word (pages of the class that may have free blocks). What is not indexed is the level above: which of a shard's segments may have pages of a class.

| Path | Before Stage D | After D1 and D2 | Counter |
|---|---|---|---|
| Refill with a valid cursor | one page, no search | the same; trimming no longer drops cursors, so more refills stay here | `SearchStats::cursor_claims` |
| Refill whose cursor page ran dry | walk of the shard's segment list, one `load` of `SEG_AVAIL + c` and `SEG_CLS + c` per segment | unchanged | `page_searches`, `page_search_segments` |
| Refill after trimming | the same walk (trimming dropped every cursor) | only if trimming released the cursor's page | `cursor_invalidations` |
| Trimming a shard | every small page of every segment checked | the candidates only (plus every small page on reconciling sweeps); still one visit per owned segment for the empty-segment rule | `trim_pages_inspected`, `segments_inspected` |

So the remaining search cost is `page_search_segments`: per page search, the number of segments the shard owns in front of the first one with a usable page. It is small when a shard owns few segments (the common case: the arena holds 16,384 segments for 64 shards) and grows linearly with a shard's segment count. Without traces of a real workload (Gate D, OxiBelt load, cannot run yet) there is no evidence either way that it matters, which is why D3 stops at a design.

## 2. Representation and metadata budget

The brief rules out a dense product: a 16,384-bit segment bitmap per class is 2 KiB, 64 KiB for 32 classes, and 4 MiB if duplicated for 64 shards.

Proposed: **shard-local slots.**

- Each segment a shard owns gets a slot `0..63` in that shard, taken from a per-shard `slots: AtomicU64` (1 = in use) when the segment is linked, and given back when trimming unlinks it. The slot is stored in the reserved header word `[6]` (`SEG_SLOT`, slot + 1, 0 = none).
- Per shard and class, one `AtomicU64` whose bit `s` means "the segment in slot `s` may have pages of this class with free blocks".
- A shard that owns more than 64 segments gives the extra ones no slot. They stay reachable through the list walk, which then serves as the fallback (below).

| Item | Size |
|---|---|
| Class words: 64 shards x 32 classes x 8 bytes | 16 KiB |
| Slot words: 64 shards x 8 bytes | 512 bytes |
| Segment header | one reserved word, already allocated |
| Total | about 16.5 KiB, in the `Heap` (static), no per-segment growth |

The existing page summaries and availability words stay the lower levels; the index only names segments.

## 3. Publication and clearing

The index is updated on transitions, never on every free, and only by the shard that owns the segment or by the free that makes a segment's availability word non-zero.

- **Publish.** `proto::release_blocks` already sets the page's availability bit on the page's summary transition (zero to non-zero). With the index, when that `fetch_or` on `SEG_AVAIL + c` returns 0 (the segment had no available page of the class), the freer reads `SEG_HDR` and `SEG_SLOT` and sets the slot bit in the owning shard's class word. One extra read and one `fetch_or` per segment-level transition; nothing on other frees.
- **Clear (owner, under the shard lock).** When the search finds a slot's segment without a usable page, it clears the slot bit first, then removes stale bits of pages that are not of the class from the availability word (`fetch_and(SEG_CLS + c)`; `SEG_CLS` only changes under this lock), then re-reads the availability word with a read-modify-write, as `proto::retire_page` does, and sets the slot bit again if a page of the class became available. A free racing the clear either lands before the re-read (and the owner re-publishes) or finds the availability word at zero and publishes itself. Removing the stale bits is what keeps the "zero to non-zero" trigger honest: a leftover bit of a page from a previous life would otherwise suppress the publish of a real one.
- **Stale ownership.** Segments are recycled (returned to the arena, reacquired by another shard or as a huge block). A late free into a recycled segment can publish into whatever slot and shard the header names at that moment. That is a stale positive, never a loss: every candidate is validated under the owner's lock against the authoritative words (`SEG_HDR` kind and shard, `SEG_SLOT`, `SEG_CLS + c`, the page summary). No generation tags are needed for that reason; a returned segment's slot bit is cleared in every class word of its shard when the slot is given back, under the same lock.

## 4. Fallback before growth or exhaustion

A search that finds nothing through the index walks the shard's segment list, as `find_page` does today, before it sets up a new page or reports out of memory. Hits in that walk are counted (`index_misses`); they are expected only for slotless segments (a shard with more than 64) and would signal a lost publication otherwise. The fallback keeps the index an optimisation: a wrong or empty hint can cost time, never capacity.

## 5. Verification it would need

- Loom models of the publish and clear helpers in `proto.rs`, driven through the production functions: a free making the availability word non-zero racing a clear; a late free into a segment being recycled; two freers publishing into one class word.
- The model (`model.rs`, fuzz target) comparing, at every quiescent point, the indexed search with the authoritative list walk: whenever the walk finds a usable page of a class, the index must name its segment (or the segment must be slotless). Generated fragmented heaps with full-to-nonfull transitions, class reuse at the same page offset, and segment return and reacquisition, as for D1 and D2.
- `index_misses == 0` asserted in the single-threaded model, as `reconciled_pages == 0` is asserted for D2.

## 6. Remaining costs it would not remove

- The owner's lock: every refill that searches still takes the shard lock.
- A bit scan of one class word per search, plus one validation per candidate segment; stale candidates cost a clear and a re-read each.
- The list walk for shards with more than 64 segments, and for validation failures.
- Trimming's one visit per owned segment (empty-segment ageing and return), which the index does not cover.
- On the free path: one header read and one `fetch_or` on each segment-level availability transition.

## 7. When to build it

When the counters of a real workload show page searches walking many segments (a high `page_search_segments / page_searches`), or when the owner asks for it. Measuring that needs traces or benchmarks, which this plan leaves disabled; nothing in this design depends on them.
