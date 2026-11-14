//! AArch64 kernels for the thread cache's block list: Armv8.0-A with
//! Advanced SIMD, the `aarch64-unknown-linux-gnu` baseline (no SVE, nothing
//! newer). Self-contained: no `crate::` paths, so the benchmark crate can
//! include this file too.
//!
//! Both kernels are inline assembly, so they are part of the paths that
//! use them. They use the integer registers the compiler picks for their
//! operands and the caller-saved vector registers `v0`-`v4` and
//! `v16`-`v24`, never `v8`-`v15` (whose low halves a caller must preserve),
//! the frame pointer or the link register, and they do not touch the
//! stack. Neither reads a lookup table: every constant is an immediate.
//! Measured on an Apple M3, a 16-byte literal for either kernel's one
//! vector constant was no faster than building it.

use core::cell::Cell;

// The byte order of the integer registers the kernels move to and from
// vector registers and store as words (docs/platform.md).
const _: () = assert!(cfg!(target_endian = "little"));

/// Reported by the tests and the benchmark.
#[allow(
  dead_code,
  reason = "read by the allocator's tests and by the benchmark that includes this file"
)]
pub(crate) const NAME: &str =
  "aarch64 NEON (cmeq + sri match mask, scalar length mask; nibble ranks + st4 lane stores)";

/// Whether block number `i` (below 64) is among the first `len` (at most
/// 64) entries of `blocks`.
///
/// Four `cmeq` mark the entries equal to `i` in `v0`-`v3` (entries 0-15,
/// 16-31, 32-47 and 48-63). Three `sri` gather, for each `j` below 16, the
/// marks of the entries `j`, `16 + j`, `32 + j` and `48 + j` into the high
/// nibble of byte `j`; a fourth copies it to the low nibble and `shrn`
/// narrows the 16 bytes to 64 bits, so bit `4j + q` of the result says that
/// entry `16q + j` is `i`. No instruction puts the marks in entry order
/// cheaply (`ld4` would, at several times the cost of the two `ldp`), so
/// the length is brought to the marks' order instead, in integer registers:
/// with `len = 16a + b`, entry `16q + j` is live when `q < a`, or `q == a`
/// and `j < b`. `R` has bit 0 of every nibble set; `(R << a) - R` (modulo
/// 2^64, which makes it all ones for `a == 4`) has the bits `q < a` of
/// every nibble, and `R << a` below bit `4b` has bit `a` of the nibbles
/// `j < b`. The result is the marks under that mask.
#[inline(always)]
pub(crate) fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  let live: u64;
  // SAFETY: `p` comes from a shared borrow of 64 `Cell<u8>`, which have the
  // layout of 64 bytes, and the two `ldp` read exactly those 64 bytes, at
  // any alignment; nothing is written to memory and the stack is not used.
  // `dup` reads only the low byte of `i`'s register, and `len` is passed
  // zero-extended. The block changes its four integer outputs and `v0` to
  // `v4`, all declared, and sets no flags.
  unsafe {
    core::arch::asm!(
      "ldp q0, q1, [{p}]",
      "ldp q2, q3, [{p}, #32]",
      "dup v4.16b, {i:w}",
      "cmeq v0.16b, v0.16b, v4.16b",
      "cmeq v1.16b, v1.16b, v4.16b",
      "cmeq v2.16b, v2.16b, v4.16b",
      "cmeq v3.16b, v3.16b, v4.16b",
      "sri v1.16b, v0.16b, #1",
      "sri v3.16b, v2.16b, #1",
      "sri v3.16b, v1.16b, #2",
      "sri v3.16b, v3.16b, #4",
      "shrn v3.8b, v3.8h, #4",
      // The live entries, in the layout of the marks.
      "mov {r}, #0x1111111111111111",
      "lsr {a}, {len}, #4",
      "ubfiz {b}, {len}, #2, #4",
      "mov {m}, #-1",
      "lsl {a}, {r}, {a}",
      "lsl {m}, {m}, {b}",
      "sub {r}, {a}, {r}",
      "bic {a}, {a}, {m}",
      "orr {a}, {a}, {r}",
      "fmov {r}, d3",
      "and {r}, {r}, {a}",
      p = in(reg) blocks.as_ptr(),
      i = in(reg) i,
      len = in(reg) u64::from(len),
      r = out(reg) live,
      a = out(reg) _,
      b = out(reg) _,
      m = out(reg) _,
      out("v0") _,
      out("v1") _,
      out("v2") _,
      out("v3") _,
      out("v4") _,
      options(pure, readonly, nostack, preserves_flags),
    );
  }
  live != 0
}

/// Writes the numbers of the set bits of `bits` to `blocks`, highest
/// first, and returns their count.
///
/// Four cases, chosen by the number of set bits, each without a loop:
///
/// - At most one: a `clz` and one byte store, in integer registers only.
/// - At most four, and at most eight: one or two groups of four `clz`
///   steps. A group gathers its four numbers in one register and stores
///   them as a word; a step past the last set bit yields a byte past the
///   count, which no reader looks at.
/// - More: the vector path. The word's 16 nibbles become 16 bytes, highest
///   first, and the numbers of each nibble's set bits are worked out for
///   all 16 at once, highest first: `clz` gives the highest, `clz` again
///   after clearing it gives the second, the third is bit 1 for the
///   nibbles 14 and 15 and bit 0 otherwise, and a fourth can only be
///   bit 0. With the number of the nibble's lowest bit added, `v0`-`v3`
///   hold one rank each. A four-byte `st4` of one lane then stores one
///   nibble's four numbers at the list's end so far, and the end advances
///   by the nibble's population count (a SWAR count in an integer
///   register), so the next store overwrites what was not a set bit.
///
/// The count comes from `cnt` and `addv`; the first case does without.
#[inline(always)]
pub(crate) fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  let n: u64;
  // SAFETY: `p` comes from a shared borrow of 64 `Cell<u8>`, which have the
  // layout of 64 bytes and may be written through a shared borrow; the list
  // belongs to the calling thread. The first case writes byte 0, the second
  // the bytes 0 to 3 and the third the bytes 0 to 7. On the vector path,
  // store `k` (0 to 15) writes the four bytes that start at the sum of the
  // population counts of the `k` nibbles above its own, which is at most
  // `4k`, so every write is inside the 64 bytes. Nothing is read from
  // memory and the stack is not used. The block changes the flags, its
  // seven integer operands and `v0`-`v3` and `v16`-`v24`, all declared;
  // `bits` and what is derived from it are only ever in registers.
  unsafe {
    core::arch::asm!(
      // At most one set bit: its number, or a byte past the count of 0.
      "sub {t}, {bits}, #1",
      "tst {t}, {bits}",
      "b.ne 5f",
      "clz {t}, {bits}",
      "cmp {bits}, #0",
      "eor {t:w}, {t:w}, #63",
      "cset {n:w}, ne",
      "strb {t:w}, [{p}]",
      "b 3f",
      "5:",
      "fmov d16, {bits}",
      "cnt v17.8b, v16.8b",
      "addv b17, v17.8b",
      "fmov {n:w}, s17",
      "cmp {n:w}, #8",
      "b.hi 2f",
      // At most eight: `63 - clz` of the highest four, one per byte of
      // `a`, each cleared from `bits` in turn.
      "mov {u}, #0x8000000000000000",
      "clz {a}, {bits}",
      "lsr {c}, {u}, {a}",
      "bic {bits}, {bits}, {c}",
      "clz {t}, {bits}",
      "lsr {c}, {u}, {t}",
      "bic {bits}, {bits}, {c}",
      "orr {a:w}, {a:w}, {t:w}, lsl #8",
      "clz {t}, {bits}",
      "lsr {c}, {u}, {t}",
      "bic {bits}, {bits}, {c}",
      "orr {a:w}, {a:w}, {t:w}, lsl #16",
      "clz {t}, {bits}",
      "orr {a:w}, {a:w}, {t:w}, lsl #24",
      "eor {a:w}, {a:w}, #0x3f3f3f3f",
      "str {a:w}, [{p}]",
      "cmp {n:w}, #4",
      "b.ls 3f",
      // The next four.
      "lsr {c}, {u}, {t}",
      "bic {bits}, {bits}, {c}",
      "clz {a}, {bits}",
      "lsr {c}, {u}, {a}",
      "bic {bits}, {bits}, {c}",
      "clz {t}, {bits}",
      "lsr {c}, {u}, {t}",
      "bic {bits}, {bits}, {c}",
      "orr {a:w}, {a:w}, {t:w}, lsl #8",
      "clz {t}, {bits}",
      "lsr {c}, {u}, {t}",
      "bic {bits}, {bits}, {c}",
      "orr {a:w}, {a:w}, {t:w}, lsl #16",
      "clz {t}, {bits}",
      "orr {a:w}, {a:w}, {t:w}, lsl #24",
      "eor {a:w}, {a:w}, #0x3f3f3f3f",
      "str {a:w}, [{p}, #4]",
      "b 3f",
      "2:",
      // c: the population count of each nibble, in the nibble.
      "lsr {t}, {bits}, #1",
      "and {t}, {t}, #0x5555555555555555",
      "sub {t}, {bits}, {t}",
      "lsr {u}, {t}, #2",
      "and {t}, {t}, #0x3333333333333333",
      "and {u}, {u}, #0x3333333333333333",
      "add {c}, {t}, {u}",
      // v3: the number of each nibble's lowest bit, 60 down to 0.
      "mov {t}, #0x383c",
      "movk {t}, #0x3034, lsl #16",
      "movk {t}, #0x282c, lsl #32",
      "movk {t}, #0x2024, lsl #48",
      "mov {u}, #0x2020202020202020",
      "fmov d3, {t}",
      "sub {t}, {t}, {u}",
      "mov v3.d[1], {t}",
      // v16: the nibbles as bytes, highest first.
      "rev64 v16.8b, v16.8b",
      "movi v20.16b, #15",
      "movi v21.16b, #7",
      "movi v22.16b, #1",
      "movi v23.16b, #13",
      "ushr v17.8b, v16.8b, #4",
      "and v16.8b, v16.8b, v20.8b",
      "zip1 v16.16b, v17.16b, v16.16b",
      "add v24.16b, v3.16b, v21.16b",
      // v0: the highest set bit of each nibble; v1: the second; v2: the
      // third; v3: the fourth.
      "clz v17.16b, v16.16b",
      "eor v18.16b, v17.16b, v21.16b",
      "sub v0.16b, v24.16b, v17.16b",
      "ushl v18.16b, v22.16b, v18.16b",
      "bic v18.16b, v16.16b, v18.16b",
      "clz v18.16b, v18.16b",
      "sub v1.16b, v24.16b, v18.16b",
      "cmhi v19.16b, v16.16b, v23.16b",
      "sub v2.16b, v3.16b, v19.16b",
      // One nibble's four numbers at a time, at the list's end so far.
      "ubfx {t}, {c}, #60, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[0], [{p}], {t}",
      "ubfx {t}, {c}, #56, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[1], [{p}], {t}",
      "ubfx {t}, {c}, #52, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[2], [{p}], {t}",
      "ubfx {t}, {c}, #48, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[3], [{p}], {t}",
      "ubfx {t}, {c}, #44, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[4], [{p}], {t}",
      "ubfx {t}, {c}, #40, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[5], [{p}], {t}",
      "ubfx {t}, {c}, #36, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[6], [{p}], {t}",
      "ubfx {t}, {c}, #32, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[7], [{p}], {t}",
      "ubfx {t}, {c}, #28, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[8], [{p}], {t}",
      "ubfx {t}, {c}, #24, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[9], [{p}], {t}",
      "ubfx {t}, {c}, #20, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[10], [{p}], {t}",
      "ubfx {t}, {c}, #16, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[11], [{p}], {t}",
      "ubfx {t}, {c}, #12, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[12], [{p}], {t}",
      "ubfx {t}, {c}, #8, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[13], [{p}], {t}",
      "ubfx {t}, {c}, #4, #4",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[14], [{p}], {t}",
      "st4 {{v0.b, v1.b, v2.b, v3.b}}[15], [{p}]",
      "3:",
      bits = inout(reg) bits => _,
      p = inout(reg) blocks.as_ptr() => _,
      n = out(reg) n,
      t = out(reg) _,
      u = out(reg) _,
      c = out(reg) _,
      a = out(reg) _,
      out("v0") _,
      out("v1") _,
      out("v2") _,
      out("v3") _,
      out("v16") _,
      out("v17") _,
      out("v18") _,
      out("v19") _,
      out("v20") _,
      out("v21") _,
      out("v22") _,
      out("v23") _,
      out("v24") _,
      options(nostack),
    );
  }
  n as u8
}

/// PLACEHOLDER (portable loop), to be replaced by assembly: bit `i` is set
/// iff `words[i]` is non-zero. `words.len()` is at most 64.
#[inline(always)]
pub(crate) fn nonzero_words(words: &[core::sync::atomic::AtomicU64]) -> u64 {
  let mut mask = 0;
  for (i, w) in words.iter().enumerate() {
    mask |= u64::from(w.load(core::sync::atomic::Ordering::Relaxed) != 0) << i;
  }
  mask
}

/// PLACEHOLDER (portable loop), to be replaced by assembly: the mask of the
/// block numbers (each below 64) in the first `len` (at most 64) entries.
#[inline(always)]
pub(crate) fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  blocks[..usize::from(len)]
    .iter()
    .fold(0, |m, b| m | 1 << b.get())
}
