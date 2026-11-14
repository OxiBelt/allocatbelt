//! AArch64 kernels for the thread cache's block list and for a page's
//! bitmap words: Armv8.0-A with Advanced SIMD, the
//! `aarch64-unknown-linux-gnu` baseline (no SVE, nothing newer).
//! Self-contained: no `crate::` paths, so the benchmark crate can include
//! this file too.
//!
//! The kernels are inline assembly, so they are part of the paths that
//! use them. They use the integer registers the compiler picks for their
//! operands and the caller-saved vector registers `v0`-`v7` and
//! `v16`-`v24`, never `v8`-`v15` (whose low halves a caller must preserve),
//! the frame pointer or the link register, and they do not touch the
//! stack. None reads a lookup table: every constant is an immediate.
//! Measured on an Apple M3, a 16-byte literal for the one vector constant
//! of `list_holds` or of `unpack_blocks` was no faster than building it.

use core::cell::Cell;

// The byte order of the integer registers the kernels move to and from
// vector registers and store as words (docs/platform.md).
const _: () = assert!(cfg!(target_endian = "little"));

/// Reported by the tests and the benchmark.
#[allow(
  dead_code,
  reason = "read by the allocator's tests and by the benchmark that includes this file"
)]
pub(crate) const NAME: &str = "aarch64 NEON (cmeq + sri match mask, scalar length mask; nibble ranks + st4 lane stores; \
   cmp/adc chains to 16 words, umaxp + addp from 17; ushl one-hot halves)";

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

/// Which of `words` are non-zero: bit `i` of the result is set iff
/// `words[i]` is not zero. `words.len()` is at most 64. The loads are plain
/// ones: the caller holds the lock under which the words change.
///
/// The length picks one of seven cases, each without a loop and each
/// reading only the words of the slice. A case past two words covers the
/// lengths `h + 1` to `2h` (`h` is 2, 4, 8, 16 or 32) with the first `h`
/// words and the last `h`, which overlap unless the length is `2h`: the
/// mask of the last `h`, shifted by `len - h`, is ORed onto the mask of the
/// first `h`, and a word in both gives the same bit twice.
///
/// - Up to 16 words, in integer registers: `cmp x, #1` sets the carry iff
///   `x` is not zero and `adc r, r, r` shifts it into a mask, highest word
///   first, at most four words to a chain.
/// - 17 to 64 words, 16 words to a vector: a 64-bit word is zero iff the
///   larger of its 32-bit halves is, so `umaxp` on 32-bit lanes narrows
///   four words to four lanes that are zero where the words are, and
///   `umaxp` on 16-bit and on 8-bit lanes brings 16 words to 16 bytes.
///   `cmtst` and `and` leave bit `j mod 8` in byte `j` for a non-zero
///   word, and three `addp` add the eight bytes of each half into one: 16
///   mask bits per vector, in word order.
///
/// The integer chains go as far as 16 words because, measured on an Apple
/// M3 with each call's address depending on the previous call's mask, the
/// vector path's mask for 16 words was ready later than the chains' and
/// than the portable loop's, although it takes fewer instructions. For 32
/// words it was ready about a nanosecond after the chains', with half the
/// instructions, and for 64 words before them.
#[inline(always)]
pub(crate) fn nonzero_words(words: &[core::sync::atomic::AtomicU64]) -> u64 {
  let mask: u64;
  // SAFETY: `p` and `n` are the pointer and the length of a shared slice of
  // `AtomicU64`, which have the layout of aligned `u64`. Every load is
  // inside the slice: the case for the lengths `h + 1` to `2h` reads the
  // `h` words that start at `p` and the `h` that end at `p + 8n`, the
  // cases for one and for two words read exactly those, and an empty slice
  // is not read. A length above 64 takes the last case, whose loads are
  // still inside the slice (its result means nothing). Each load is of
  // whole aligned words, which the caller's lock keeps others from
  // writing. Nothing is written to memory and the stack is not used. The
  // block changes the flags, its seven integer operands and `v0`-`v7` and
  // `v16`-`v20`, all declared.
  unsafe {
    core::arch::asm!(
      "cmp {n}, #4",
      "b.hi 4f",
      "cmp {n}, #2",
      "b.hi 3f",
      "b.eq 2f",
      // No word, or one.
      "mov {r}, #0",
      "cbz {n}, 9f",
      "ldr {a}, [{p}]",
      "cmp {a}, #0",
      "cset {r:w}, ne",
      "b 9f",
      // Two: the carry of `cmp x, #1` is set when `x` is not zero.
      "2:",
      "ldp {a}, {b}, [{p}]",
      "cmp {b}, #0",
      "cset {r:w}, ne",
      "cmp {a}, #1",
      "adc {r}, {r}, {r}",
      "b 9f",
      // Three or four: the first two and the last two.
      "3:",
      "add {e}, {p}, {n}, lsl #3",
      "ldp {a}, {b}, [{p}]",
      "cmp {b}, #0",
      "cset {r:w}, ne",
      "cmp {a}, #1",
      "adc {r}, {r}, {r}",
      "ldp {a}, {b}, [{e}, #-16]",
      "cmp {b}, #0",
      "cset {h:w}, ne",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "sub {n}, {n}, #2",
      "lsl {h}, {h}, {n}",
      "orr {r}, {r}, {h}",
      "b 9f",
      "4:",
      "add {e}, {p}, {n}, lsl #3",
      "cmp {n}, #8",
      "b.hi 5f",
      // Five to eight: the first four and the last four.
      "ldp {a}, {b}, [{p}, #16]",
      "cmp {b}, #0",
      "cset {r:w}, ne",
      "cmp {a}, #1",
      "adc {r}, {r}, {r}",
      "ldp {a}, {b}, [{p}]",
      "cmp {b}, #1",
      "adc {r}, {r}, {r}",
      "cmp {a}, #1",
      "adc {r}, {r}, {r}",
      "ldp {a}, {b}, [{e}, #-16]",
      "cmp {b}, #0",
      "cset {h:w}, ne",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "ldp {a}, {b}, [{e}, #-32]",
      "cmp {b}, #1",
      "adc {h}, {h}, {h}",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "sub {n}, {n}, #4",
      "lsl {h}, {h}, {n}",
      "orr {r}, {r}, {h}",
      "b 9f",
      "5:",
      "cmp {n}, #16",
      "b.hi 6f",
      // Nine to 16: the first eight and the last eight, four words to a
      // chain. `p` is free once the first eight are loaded.
      "ldp {a}, {b}, [{p}, #16]",
      "cmp {b}, #0",
      "cset {r:w}, ne",
      "cmp {a}, #1",
      "adc {r}, {r}, {r}",
      "ldp {a}, {b}, [{p}]",
      "cmp {b}, #1",
      "adc {r}, {r}, {r}",
      "cmp {a}, #1",
      "adc {r}, {r}, {r}",
      "ldp {a}, {b}, [{p}, #48]",
      "cmp {b}, #0",
      "cset {h:w}, ne",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "ldp {a}, {b}, [{p}, #32]",
      "cmp {b}, #1",
      "adc {h}, {h}, {h}",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "orr {r}, {r}, {h}, lsl #4",
      "ldp {a}, {b}, [{e}, #-48]",
      "cmp {b}, #0",
      "cset {h:w}, ne",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "ldp {a}, {b}, [{e}, #-64]",
      "cmp {b}, #1",
      "adc {h}, {h}, {h}",
      "cmp {a}, #1",
      "adc {h}, {h}, {h}",
      "ldp {a}, {b}, [{e}, #-16]",
      "cmp {b}, #0",
      "cset {p:w}, ne",
      "cmp {a}, #1",
      "adc {p}, {p}, {p}",
      "ldp {a}, {b}, [{e}, #-32]",
      "cmp {b}, #1",
      "adc {p}, {p}, {p}",
      "cmp {a}, #1",
      "adc {p}, {p}, {p}",
      "orr {h}, {h}, {p}, lsl #4",
      "sub {n}, {n}, #8",
      "lsl {h}, {h}, {n}",
      "orr {r}, {r}, {h}",
      "b 9f",
      // v20: the bit of each byte position in its 64-bit half.
      "6:",
      "mov {a}, #0x0201",
      "movk {a}, #0x0804, lsl #16",
      "movk {a}, #0x2010, lsl #32",
      "movk {a}, #0x8040, lsl #48",
      "dup v20.2d, {a}",
      "cmp {n}, #32",
      "b.hi 7f",
      // 17 to 32: the first 16 (v16) and the last 16 (v17).
      "ldp q0, q1, [{p}]",
      "ldp q2, q3, [{p}, #32]",
      "ldp q4, q5, [{p}, #64]",
      "ldp q6, q7, [{p}, #96]",
      "umaxp v0.4s, v0.4s, v1.4s",
      "umaxp v2.4s, v2.4s, v3.4s",
      "umaxp v4.4s, v4.4s, v5.4s",
      "umaxp v6.4s, v6.4s, v7.4s",
      "umaxp v0.8h, v0.8h, v2.8h",
      "umaxp v4.8h, v4.8h, v6.8h",
      "umaxp v16.16b, v0.16b, v4.16b",
      "ldp q0, q1, [{e}, #-128]",
      "ldp q2, q3, [{e}, #-96]",
      "ldp q4, q5, [{e}, #-64]",
      "ldp q6, q7, [{e}, #-32]",
      "umaxp v0.4s, v0.4s, v1.4s",
      "umaxp v2.4s, v2.4s, v3.4s",
      "umaxp v4.4s, v4.4s, v5.4s",
      "umaxp v6.4s, v6.4s, v7.4s",
      "umaxp v0.8h, v0.8h, v2.8h",
      "umaxp v4.8h, v4.8h, v6.8h",
      "umaxp v17.16b, v0.16b, v4.16b",
      "cmtst v16.16b, v16.16b, v16.16b",
      "cmtst v17.16b, v17.16b, v17.16b",
      "and v16.16b, v16.16b, v20.16b",
      "and v17.16b, v17.16b, v20.16b",
      "addp v16.16b, v16.16b, v17.16b",
      "addp v16.16b, v16.16b, v16.16b",
      "addp v16.16b, v16.16b, v16.16b",
      "fmov {a:w}, s16",
      "sub {n}, {n}, #16",
      "lsr {b:w}, {a:w}, #16",
      "and {r:w}, {a:w}, #0xffff",
      "lsl {b}, {b}, {n}",
      "orr {r}, {r}, {b}",
      "b 9f",
      // 33 to 64: the first 32 (v16, v17) and the last 32 (v18, v19).
      "7:",
      "ldp q0, q1, [{p}]",
      "ldp q2, q3, [{p}, #32]",
      "ldp q4, q5, [{p}, #64]",
      "ldp q6, q7, [{p}, #96]",
      "umaxp v0.4s, v0.4s, v1.4s",
      "umaxp v2.4s, v2.4s, v3.4s",
      "umaxp v4.4s, v4.4s, v5.4s",
      "umaxp v6.4s, v6.4s, v7.4s",
      "umaxp v0.8h, v0.8h, v2.8h",
      "umaxp v4.8h, v4.8h, v6.8h",
      "umaxp v16.16b, v0.16b, v4.16b",
      "ldp q0, q1, [{p}, #128]",
      "ldp q2, q3, [{p}, #160]",
      "ldp q4, q5, [{p}, #192]",
      "ldp q6, q7, [{p}, #224]",
      "umaxp v0.4s, v0.4s, v1.4s",
      "umaxp v2.4s, v2.4s, v3.4s",
      "umaxp v4.4s, v4.4s, v5.4s",
      "umaxp v6.4s, v6.4s, v7.4s",
      "umaxp v0.8h, v0.8h, v2.8h",
      "umaxp v4.8h, v4.8h, v6.8h",
      "umaxp v17.16b, v0.16b, v4.16b",
      "ldp q0, q1, [{e}, #-256]",
      "ldp q2, q3, [{e}, #-224]",
      "ldp q4, q5, [{e}, #-192]",
      "ldp q6, q7, [{e}, #-160]",
      "umaxp v0.4s, v0.4s, v1.4s",
      "umaxp v2.4s, v2.4s, v3.4s",
      "umaxp v4.4s, v4.4s, v5.4s",
      "umaxp v6.4s, v6.4s, v7.4s",
      "umaxp v0.8h, v0.8h, v2.8h",
      "umaxp v4.8h, v4.8h, v6.8h",
      "umaxp v18.16b, v0.16b, v4.16b",
      "ldp q0, q1, [{e}, #-128]",
      "ldp q2, q3, [{e}, #-96]",
      "ldp q4, q5, [{e}, #-64]",
      "ldp q6, q7, [{e}, #-32]",
      "umaxp v0.4s, v0.4s, v1.4s",
      "umaxp v2.4s, v2.4s, v3.4s",
      "umaxp v4.4s, v4.4s, v5.4s",
      "umaxp v6.4s, v6.4s, v7.4s",
      "umaxp v0.8h, v0.8h, v2.8h",
      "umaxp v4.8h, v4.8h, v6.8h",
      "umaxp v19.16b, v0.16b, v4.16b",
      "cmtst v16.16b, v16.16b, v16.16b",
      "cmtst v17.16b, v17.16b, v17.16b",
      "cmtst v18.16b, v18.16b, v18.16b",
      "cmtst v19.16b, v19.16b, v19.16b",
      "and v16.16b, v16.16b, v20.16b",
      "and v17.16b, v17.16b, v20.16b",
      "and v18.16b, v18.16b, v20.16b",
      "and v19.16b, v19.16b, v20.16b",
      "addp v16.16b, v16.16b, v17.16b",
      "addp v18.16b, v18.16b, v19.16b",
      "addp v16.16b, v16.16b, v18.16b",
      "addp v16.16b, v16.16b, v16.16b",
      "fmov {a}, d16",
      "sub {n}, {n}, #32",
      "lsr {b}, {a}, #32",
      "mov {r:w}, {a:w}",
      "lsl {b}, {b}, {n}",
      "orr {r}, {r}, {b}",
      "9:",
      p = inout(reg) words.as_ptr() => _,
      n = inout(reg) words.len() => _,
      r = out(reg) mask,
      a = out(reg) _,
      b = out(reg) _,
      e = out(reg) _,
      h = out(reg) _,
      out("v0") _,
      out("v1") _,
      out("v2") _,
      out("v3") _,
      out("v4") _,
      out("v5") _,
      out("v6") _,
      out("v7") _,
      out("v16") _,
      out("v17") _,
      out("v18") _,
      out("v19") _,
      out("v20") _,
      options(pure, readonly, nostack),
    );
  }
  mask
}

/// The mask of the block numbers (each below 64) in the first `len` entries
/// of `blocks`: the OR of `1 << blocks[k]` for `k` below `len`. A `len`
/// above 64 counts as 64.
///
/// - No entry: zero after one branch. A flush packs the list of every
///   class, and most are empty.
/// - One to seven: one, two and four entries at a time in integer
///   registers, an `lsl` of 1 and an `orr` for each.
/// - Eight or more: `ushl` shifts each 64-bit half of a vector by the low
///   byte of the same half of another, so one `ushl` of two ones makes the
///   bits of two entries, and `orr` gathers them. Only entries below `len`
///   are ever such a low byte, in one of two ways. The last 16 entries are
///   loaded once and shifted right by one to seven bytes, since a load
///   with one of the last seven entries as a low byte would run past the
///   list; for fewer than 16, the two halves are the first eight entries
///   and the last eight. The entries before the last 16 come 16 at a time
///   from the first, as the low bytes of eight loads one byte apart. An
///   entry that is covered twice gives the same bit twice.
#[inline(always)]
pub(crate) fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  let bits: u64;
  // SAFETY: `p` comes from a shared borrow of 64 `Cell<u8>`, which have the
  // layout of 64 bytes, and `len` is passed zero-extended and at most 64.
  // Every load is inside those 64 bytes, at any alignment: the integer path
  // reads the first `len` bytes; the vector path reads the 16 bytes that
  // end at `len` (for a `len` below 16, the eight that start the list and
  // the eight that end at `len`), and the loop, for each `c` with
  // `16c + 16 < len`, the bytes `16c` to `16c + 22`, at most byte 54.
  // Nothing is written to memory and the stack is not used. The block
  // changes the flags, its six integer operands and `v0`-`v7`, `v16` and
  // `v17`, all declared.
  unsafe {
    core::arch::asm!(
      "mov {r}, #0",
      "cbz {len}, 9f",
      "mov {one}, #1",
      "cmp {len}, #8",
      "b.hs 4f",
      // One to seven entries: one, two and four at a time, in the integer
      // registers. A shift takes the low six bits of its count, so the
      // first entry of a group needs no extraction.
      "tbz {len:w}, #0, 2f",
      "ldrb {x:w}, [{p}], #1",
      "lsl {r}, {one}, {x}",
      "2:",
      "tst {len:w}, #6",
      "b.eq 9f",
      "tbz {len:w}, #1, 3f",
      "ldrh {x:w}, [{p}], #2",
      "lsl {t}, {one}, {x}",
      "orr {r}, {r}, {t}",
      "lsr {x}, {x}, #8",
      "lsl {t}, {one}, {x}",
      "orr {r}, {r}, {t}",
      "3:",
      "tbz {len:w}, #2, 9f",
      "ldr {x:w}, [{p}]",
      "lsl {t}, {one}, {x}",
      "orr {r}, {r}, {t}",
      "lsr {t}, {x}, #8",
      "lsl {t}, {one}, {t}",
      "orr {r}, {r}, {t}",
      "lsr {t}, {x}, #16",
      "lsl {t}, {one}, {t}",
      "orr {r}, {r}, {t}",
      "lsr {t}, {x}, #24",
      "lsl {t}, {one}, {t}",
      "orr {r}, {r}, {t}",
      "b 9f",
      // Eight or more. v16: 1 in both halves. v0: the last 16 entries, or
      // for fewer than 16 the first eight and the last eight.
      "4:",
      "dup v16.2d, {one}",
      "add {x}, {p}, {len}",
      "cmp {len}, #16",
      "b.hs 5f",
      "ldr d0, [{p}]",
      "ldur d1, [{x}, #-8]",
      "mov v0.d[1], v1.d[0]",
      "b 6f",
      "5:",
      "ldur q0, [{x}, #-16]",
      // Each entry of v0 in turn as the low byte of its half, the count
      // `ushl` shifts that half of v16 by.
      "6:",
      "ushr v1.2d, v0.2d, #8",
      "ushr v2.2d, v0.2d, #16",
      "ushr v3.2d, v0.2d, #24",
      "ushr v4.2d, v0.2d, #32",
      "ushr v5.2d, v0.2d, #40",
      "ushr v6.2d, v0.2d, #48",
      "ushr v7.2d, v0.2d, #56",
      "ushl v0.2d, v16.2d, v0.2d",
      "ushl v1.2d, v16.2d, v1.2d",
      "ushl v2.2d, v16.2d, v2.2d",
      "ushl v3.2d, v16.2d, v3.2d",
      "ushl v4.2d, v16.2d, v4.2d",
      "ushl v5.2d, v16.2d, v5.2d",
      "ushl v6.2d, v16.2d, v6.2d",
      "ushl v7.2d, v16.2d, v7.2d",
      "orr v0.16b, v0.16b, v1.16b",
      "orr v2.16b, v2.16b, v3.16b",
      "orr v4.16b, v4.16b, v5.16b",
      "orr v6.16b, v6.16b, v7.16b",
      "orr v0.16b, v0.16b, v2.16b",
      "orr v4.16b, v4.16b, v6.16b",
      "orr v17.16b, v0.16b, v4.16b",
      "subs {len}, {len}, #16",
      "b.ls 8f",
      // The entries before those, 16 at a time from the first: the load at
      // `p + k` has the entries `k` and `k + 8` as the low bytes.
      "7:",
      "ldr q0, [{p}]",
      "ldur q1, [{p}, #1]",
      "ldur q2, [{p}, #2]",
      "ldur q3, [{p}, #3]",
      "ldur q4, [{p}, #4]",
      "ldur q5, [{p}, #5]",
      "ldur q6, [{p}, #6]",
      "ldur q7, [{p}, #7]",
      "ushl v0.2d, v16.2d, v0.2d",
      "ushl v1.2d, v16.2d, v1.2d",
      "ushl v2.2d, v16.2d, v2.2d",
      "ushl v3.2d, v16.2d, v3.2d",
      "ushl v4.2d, v16.2d, v4.2d",
      "ushl v5.2d, v16.2d, v5.2d",
      "ushl v6.2d, v16.2d, v6.2d",
      "ushl v7.2d, v16.2d, v7.2d",
      "orr v0.16b, v0.16b, v1.16b",
      "orr v2.16b, v2.16b, v3.16b",
      "orr v4.16b, v4.16b, v5.16b",
      "orr v6.16b, v6.16b, v7.16b",
      "orr v0.16b, v0.16b, v2.16b",
      "orr v4.16b, v4.16b, v6.16b",
      "orr v0.16b, v0.16b, v4.16b",
      "orr v17.16b, v17.16b, v0.16b",
      "add {p}, {p}, #16",
      "subs {len}, {len}, #16",
      "b.hi 7b",
      "8:",
      "fmov {r}, d17",
      "mov {t}, v17.d[1]",
      "orr {r}, {r}, {t}",
      "9:",
      p = inout(reg) blocks.as_ptr() => _,
      len = inout(reg) u64::from(len.min(64)) => _,
      r = out(reg) bits,
      one = out(reg) _,
      x = out(reg) _,
      t = out(reg) _,
      out("v0") _,
      out("v1") _,
      out("v2") _,
      out("v3") _,
      out("v4") _,
      out("v5") _,
      out("v6") _,
      out("v7") _,
      out("v16") _,
      out("v17") _,
      options(pure, readonly, nostack),
    );
  }
  bits
}
