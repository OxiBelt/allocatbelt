//! The riscv64 kernels: hand-written assembly for RV64GC with the V
//! extension (RVV 1.0), the riscv64 floor (docs/platform.md). Self-contained:
//! no `crate::` paths, so the benchmark crate can include this file too.
//!
//! Section numbers below are those of the V chapter of the RISC-V
//! unprivileged specification ("V" Standard Extension for Vector
//! Operations, version 1.0).
//!
//! **One vector length for every VLEN.** `list_holds` and `unpack_blocks`
//! work on at most 64 byte elements under `e8, m4`. VLMAX = LMUL * VLEN /
//! SEW (31.3.4.2), which is 64 for the smallest VLEN the V extension allows
//! (128) and larger for every other one, and `vsetvli` sets `vl` to exactly
//! the requested length when that is at most VLMAX (31.6.3, rule 1). So a
//! request of at most 64 elements is granted in full on every
//! implementation: there is no strip-mining loop, and the rule that lets an
//! implementation pick any `vl` from `ceil(AVL / 2)` for an AVL between
//! VLMAX and twice VLMAX (rule 2) never applies. Nothing else depends on
//! VLEN: no instruction here reads or writes an element at or past `vl` in
//! memory (31.5.4), and all element indices used are below 64.
//!
//! **Strip-mining for 64-bit elements.** `nonzero_words` and `pack_blocks`
//! need one 64-bit element for each of up to 64 words or entries, which
//! `e64, m8` holds only from a VLEN of 512 (VLMAX is `VLEN / 8`: 16 for a
//! VLEN of 128). They loop instead, taking whatever `vl` each `vsetvli`
//! grants for what is left, so rule 2 does apply to them and they hold for
//! every grant it allows. Up to a few words or entries they run a scalar
//! loop and no vector instruction.
//!
//! **Vector state.** The blocks change `vl` and `vtype` and leave `vstart`
//! at zero, as every vector instruction does (31.3.7); `vxrm`, `vxsat` and
//! `fcsr` are not touched. Rust has no operand for `vl` or `vtype`: an
//! `asm!` block may change them (and `vxsat`, `vxrm` and `fflags`) exactly
//! when it does not claim `options(preserves_flags)`, which is how the
//! compiler is told to set up its own vector configuration again after the
//! block instead of assuming the one it had before. The vector registers
//! are clobber-only operands (`out("v8") _`); each block names every
//! register of the `m4` or `m8` groups it writes, since a tail-agnostic
//! write may change a whole group (31.3.4.3). Nothing is assumed about the
//! vector state on entry: each block runs `vset{i}vli` before its first
//! vector instruction. Every `vsetvli` takes its length from an operand of
//! the `reg` class, which never is `x0` (as the length register, `x0` would
//! mean "keep `vl`" or "VLMAX", 31.6.2).
//!
//! The V instructions need no `.option arch, +v`: a riscv64 build of the
//! allocator without `-C target-feature=+v` stops at a `compile_error!`, so
//! the assembler has V enabled whenever this file is compiled.

use core::cell::Cell;

/// Reported by the tests and the benchmark.
#[allow(
  dead_code,
  reason = "read by the allocator's tests and by the benchmark that includes this file"
)]
pub(crate) const NAME: &str = if cfg!(target_feature = "zbb") {
  "riscv64 V + Zbb (e8/m4: vmseq + vfirst < len; cpop, vcompress + vrgather; \
   e64/m8 loops: vmsne + vmv.x.s; vzext + vsll + vredor; scalar when short)"
} else {
  "riscv64 V (e8/m4: vmseq + vfirst < len; vcompress + vrgather; \
   e64/m8 loops: vmsne + vmv.x.s; vzext + vsll + vredor; scalar when short)"
};

/// Whether block number `i` is among the first `len` entries of `blocks`.
///
/// Five instructions, without a branch or a loop; the caller's branch on
/// the answer is one unsigned compare of the result with `len`:
///
/// ```text
/// li       first, 64
/// vsetvli  zero, first, e8, m4, ta, ma   # vl = 64
/// vle8.v   v8, (blocks)                  # all 64 entries
/// vmseq.vx v0, v8, i                     # mask bit k = (blocks[k] == i)
/// vfirst.m first, v0                     # the lowest such k, or -1
/// ```
///
/// Some entry below `len` equals `i` exactly when the first entry that
/// equals `i` is below `len`, so the stale entries at or past `len` need no
/// mask of their own: they can only supply a first match that the compare
/// with `len` rejects. No match is -1 (31.15.3), which as an unsigned
/// number is below no `len`. The vector length does not depend on `len`, so
/// the load and the compare do not wait for it, and a `len` above 64 needs
/// no clamp: it reads the same 64 entries, as in the portable form.
#[inline(always)]
pub(crate) fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  let list = blocks.as_ptr().cast::<u8>();
  let first: usize;
  // SAFETY: `list` comes from a shared borrow of the whole array, so it may
  // be read for 64 bytes (`Cell<u8>` has the layout of `u8`), and the list
  // belongs to the calling thread, so nothing writes it meanwhile. `vle8.v`
  // reads the `vl` bytes at `list` and nothing else (tail elements are not
  // accessed, 31.5.4), and `vl` is 64 whatever the arguments are: `e8, m4`
  // has VLMAX >= 64 for every VLEN >= 128, and a request of at most VLMAX
  // is granted exactly (31.6.3). The block writes no memory and uses no
  // stack (`readonly`, `nostack`), and its result depends only on its
  // operands and those bytes (`pure`). `vmseq.vx` compares with the low 8
  // bits of `i`'s register (31.10.1), so the unspecified upper bits of a
  // `u8` operand do not matter. Registers written: the output (`out`, not
  // `lateout`: it holds the length before the inputs are last read), `v0`
  // (the compare's mask) and the group `v8`-`v11`, all declared; `vl` and
  // `vtype` change and `vstart` is left zero, which the absence of
  // `preserves_flags` declares (see the module documentation). The
  // instructions exist because V is this build's baseline, checked before
  // the first allocation of the process and of each thread.
  unsafe {
    core::arch::asm!(
      "li {first}, 64",
      "vsetvli zero, {first}, e8, m4, ta, ma",
      "vle8.v v8, ({list})",
      "vmseq.vx v0, v8, {i}",
      "vfirst.m {first}, v0",
      list = in(reg) list,
      i = in(reg) i,
      first = out(reg) first,
      out("v0") _,
      out("v8") _,
      out("v9") _,
      out("v10") _,
      out("v11") _,
      options(pure, readonly, nostack),
    );
  }
  first < usize::from(len)
}

/// Writes the numbers of the set bits of `bits` to `blocks`, highest
/// first, and returns their count.
///
/// Twelve instructions, without a branch, a loop or a table, for any
/// number of set bits:
///
/// ```text
/// vsetivli     zero, 1, e64, m1, ta, ma
/// vmv.s.x      v0, bits                # mask bit k = bit k of bits
/// li           t, 64
/// vsetvli      zero, t, e8, m4, ta, ma # vl = 64
/// vid.v        v8                      # v8[k] = k
/// vcpop.m      n, v0                   # n = set bits (`cpop` with Zbb)
/// vcompress.vm v12, v8, v0             # v12[..n] = set bit numbers, rising
/// vsetvli      zero, n, e8, m4, ta, ma # vl = n
/// addi         t, n, -1
/// vrsub.vx     v8, v8, t               # v8[j] = n - 1 - j
/// vrgather.vv  v16, v12, v8            # v16[j] = v12[n - 1 - j]: falling
/// vse8.v       v16, (blocks)           # the first n entries
/// ```
///
/// A mask register holds the bit of element `k` in its bit `k`, whatever
/// SEW and LMUL are (31.4.5), so moving `bits` into element 0 of `v0` as
/// one 64-bit element makes it the mask of 64 byte elements (VLEN is at
/// least 128, so they are all in that element's register). `vcompress.vm`
/// packs in rising element order (31.16.5), and the list is wanted highest
/// first, so the packed numbers are reversed by a gather whose length is
/// their count; that also makes the store exactly `n` bytes long, so no
/// entry past the count is written and nothing stale leaves a register.
/// With Zbb the count comes from the scalar `cpop` instead of `vcpop.m`:
/// the same number of instructions, but the second `vsetvli` then waits for
/// no vector instruction.
#[inline(always)]
pub(crate) fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  let list = blocks.as_ptr().cast::<u8>().cast_mut();
  let n: usize;
  // SAFETY: `list` comes from a shared borrow of the whole array and every
  // byte of it is inside a `Cell`, so it may be written for 64 bytes
  // through that borrow; the list belongs to the calling thread. The only
  // memory access is `vse8.v`, which writes the `vl` bytes at `list`
  // (31.5.4) with `vl == n`, the population count of a 64-bit word, so at
  // most 64: both `vsetvli` requests (64 and `n`) are at most the VLMAX of
  // `e8, m4` for every VLEN >= 128 and are granted exactly (31.6.3), and
  // `vsetivli` grants 1 under `e64, m1`, which `vmv.s.x` needs to write
  // element 0 (31.16.1). Element indices stay in range: `vcpop.m` and
  // `vcompress.vm` use mask bits 0..64 of `v0`, which are `bits`; the
  // gather's indices `n - 1 - j` for `j < n` are below `n`, where
  // `vcompress.vm` wrote, and its destination overlaps neither source
  // (31.16.4). `bits` goes to `v0` only: not to memory and not to the stack,
  // which is unused (`nostack`). Registers written: the two scalar outputs
  // (`out`, so they share no register with the inputs, which are read after
  // them), `v0` and the groups `v8`-`v11`, `v12`-`v15` and `v16`-`v19`, all
  // declared; `vl` and `vtype` change and `vstart` is left zero, which the
  // absence of `preserves_flags` declares (see the module documentation).
  // The instructions exist because V is this build's baseline, as is Zbb
  // where `cpop` is used.
  unsafe {
    core::arch::asm!(
      "vsetivli zero, 1, e64, m1, ta, ma",
      "vmv.s.x v0, {bits}",
      "li {t}, 64",
      "vsetvli zero, {t}, e8, m4, ta, ma",
      "vid.v v8",
      #[cfg(not(target_feature = "zbb"))]
      "vcpop.m {n}, v0",
      #[cfg(target_feature = "zbb")]
      "cpop {n}, {bits}",
      "vcompress.vm v12, v8, v0",
      "vsetvli zero, {n}, e8, m4, ta, ma",
      "addi {t}, {n}, -1",
      "vrsub.vx v8, v8, {t}",
      "vrgather.vv v16, v12, v8",
      "vse8.v v16, ({list})",
      bits = in(reg) bits,
      list = in(reg) list,
      n = out(reg) n,
      t = out(reg) _,
      out("v0") _,
      out("v8") _,
      out("v9") _,
      out("v10") _,
      out("v11") _,
      out("v12") _,
      out("v13") _,
      out("v14") _,
      out("v15") _,
      out("v16") _,
      out("v17") _,
      out("v18") _,
      out("v19") _,
      options(nostack),
    );
  }
  n as u8
}

/// Which of `words` (at most 64) are non-zero: bit `i` of the result is
/// set iff `words[i]` is. Runs under the shard's lock, which is the lock the
/// words change under.
///
/// More than [`SCALAR_WORDS`] words go through a strip-mining loop over
/// 64-bit elements, `VLEN / 8` of them a trip (16, 32, 64 for a VLEN of 128,
/// 256, 512 or more), so 64 words take four, two or one trips:
///
/// ```text
///    neg      k, n                        # 64 - n, as a shift amount
/// 4: vsetvli  vl, n, e64, m8, ta, ma      # vl = words of this trip
///    vle64.v  v8, (p)                     # exactly vl words
///    vmsne.vi v0, v8, 0                   # mask bit j = (word j != 0)
///    vmv.x.s  w, v0                       # mask bits 0..64
///    neg      s, vl
///    sll      w, w, s                     # its low vl bits, at the top
///    srl      mask, mask, vl              # make room above the earlier trips
///    or       mask, mask, w
///    sub      n, n, vl
///    slli     s, vl, 3
///    add      p, p, s
///    bnez     n, 4b
///    srl      mask, mask, k               # down from the top
/// ```
///
/// Each trip handles whatever `vl` the implementation grants, which for a
/// request above VLMAX is any length from half the request up (31.6.3), and
/// the loads read `vl` words each, so the words read are those of the slice
/// and no others. The compare's mask has the bit of element `j` in bit `j`
/// of `v0` (31.4.5), and `vmv.x.s` under `e64` reads bits 0..64 of `v0`
/// whatever LMUL is (31.16.1). Its bits from `vl` up are the mask's tail,
/// which is agnostic under every setting and may hold old bits, ones or the
/// compare of stale elements (31.3.4.3): the left shift by `64 - vl` drops
/// them, and nothing else reads them. The trips build the result from the
/// top down: each shifts the earlier ones right by its own length and puts
/// its bits at the top, and the last shift moves all `n` to the bottom. The
/// scalar shifts use the low six bits of their amount, so `-vl` and `-n`
/// shift by `64 - vl` and `64 - n`, and by zero for a length of 64; a `vl`
/// of 64 is the first and only trip, whose right shift of a zero mask by
/// zero changes nothing.
///
/// Up to [`SCALAR_WORDS`] words take a scalar loop instead, from the last
/// word down, six instructions a word (`mask = mask << 1 | (word != 0)`):
/// the vector path costs two `m8` instructions, a `vsetvli` and a mask move
/// whatever the length is, which a core that splits an `m8` instruction
/// into eight parts does not earn back on a few words. The threshold is a
/// judgement, not a measurement: no riscv64 hardware has run this.
#[inline(always)]
pub(crate) fn nonzero_words(words: &[core::sync::atomic::AtomicU64]) -> u64 {
  debug_assert!(words.len() <= 64);
  let mask: u64;
  // SAFETY: `words.as_ptr()` may be read for `words.len()` aligned 64-bit
  // words (`AtomicU64` has the layout of `u64`), and the caller holds the
  // lock under which those words change, so nothing writes them meanwhile.
  // The block reads those words and no others. The scalar loop runs for
  // 1 to `SCALAR_WORDS` words, from `p + 8 * n - 8` down to `p`, and so
  // ends. The vector loop runs until `n` is zero; each `vle64.v` reads the
  // `vl` words at `p` and nothing past them (tail elements are not
  // accessed, 31.5.4), `vl` is at most the remaining `n` (31.6.3, 5.d) and
  // above zero while `n` is (5.b), so the loop ends, and `p` advances by
  // `8 * vl`: the words read are `words[0..n]`, once each, for any VLEN and
  // any choice of `vl`. No length is read from a register that could be
  // `x0` (operands of class `reg` never are). A slice longer than 64 words,
  // which no caller passes, is still read in bounds; only its result is
  // unspecified. The block writes no memory and uses no stack (`readonly`,
  // `nostack`), and its result depends only on its operands and those
  // words (`pure`).
  // Registers written: the scalar operands (all `out` or `inout`, so none
  // shares a register with an input that is read later), `v0` (the
  // compare's mask) and the group `v8`-`v15`, all declared; `vl` and
  // `vtype` change and `vstart` is left zero, which the absence of
  // `preserves_flags` declares (see the module documentation). The
  // instructions exist because V is this build's baseline, checked before
  // the first allocation of the process and of each thread.
  unsafe {
    core::arch::asm!(
      "li {mask}, 0",
      "li {w}, {scalar}",
      "bltu {w}, {n}, 3f",
      "beqz {n}, 5f",
      // Up to `SCALAR_WORDS` words: `s` walks from the end down to `p`.
      "slli {w}, {n}, 3",
      "add {s}, {p}, {w}",
      "2:",
      "addi {s}, {s}, -8",
      "ld {w}, 0({s})",
      "slli {mask}, {mask}, 1",
      "snez {w}, {w}",
      "or {mask}, {mask}, {w}",
      "bne {s}, {p}, 2b",
      "j 5f",
      // More words: `vl` of them a trip.
      "3:",
      "neg {k}, {n}",
      "4:",
      "vsetvli {vl}, {n}, e64, m8, ta, ma",
      "vle64.v v8, ({p})",
      "vmsne.vi v0, v8, 0",
      "vmv.x.s {w}, v0",
      "neg {s}, {vl}",
      "sll {w}, {w}, {s}",
      "srl {mask}, {mask}, {vl}",
      "or {mask}, {mask}, {w}",
      "sub {n}, {n}, {vl}",
      "slli {s}, {vl}, 3",
      "add {p}, {p}, {s}",
      "bnez {n}, 4b",
      "srl {mask}, {mask}, {k}",
      "5:",
      scalar = const SCALAR_WORDS,
      p = inout(reg) words.as_ptr() => _,
      n = inout(reg) words.len() => _,
      mask = out(reg) mask,
      w = out(reg) _,
      s = out(reg) _,
      k = out(reg) _,
      vl = out(reg) _,
      out("v0") _,
      out("v8") _,
      out("v9") _,
      out("v10") _,
      out("v11") _,
      out("v12") _,
      out("v13") _,
      out("v14") _,
      out("v15") _,
      options(pure, readonly, nostack),
    );
  }
  mask
}

/// The mask of the block numbers (each below 64) in the first `len` (at
/// most 64) entries of `blocks`: the OR of `1 << blocks[k]` for `k < len`.
///
/// More than [`SCALAR_ENTRIES`] entries go through a strip-mining loop that
/// widens `VLEN / 8` entries a trip to 64-bit elements (16, 32, 64 entries
/// for a VLEN of 128, 256, 512 or more), shifts a one by each and ORs the
/// results into element 0 of `v1`. The first trip is written out, so a
/// list that fits one trip runs no second `vsetvli`:
///
/// ```text
///    vsetvli   vl, n, e64, m8, ta, ma   # vl = entries of the first trip
///    vmv.v.i   v16, 1                   # ones, for this and shorter trips
///    vle8.v    v2, (p)                  # exactly vl entries, as bytes
///    vzext.vf8 v8, v2                   # one 64-bit element each
///    vsll.vv   v8, v16, v8              # 1 << entry
///    vredor.vs v1, v8, v8               # v1[0] = OR of the vl elements
///    sub       n, n, vl
///    beqz      n, 6f
/// 4: add       p, p, vl
///    vsetvli   vl, n, e64, m8, ta, ma   # vl = entries of this trip
///    vle8.v    v2, (p)
///    vzext.vf8 v8, v2
///    vsll.vv   v8, v16, v8
///    vredor.vs v1, v8, v1               # v1[0] |= OR of the vl elements
///    sub       n, n, vl
///    bnez      n, 4b
/// 6: vmv.x.s   mask, v1
/// ```
///
/// The byte load under `e64, m8` has EMUL 1 (31.7.3), so it reads `vl`
/// bytes into one register, the source `vzext.vf8` wants (31.11.3). Only
/// the entries below `len` are ever loaded, so the stale ones need no mask.
/// `vsll.vv` uses the low six bits of each shift amount (31.11.6), as the
/// portable form's shift does. The ones are written once, for the first
/// trip's `vl`, which no later trip exceeds: a request below twice VLMAX is
/// granted at least half of itself, and a larger one VLMAX (31.6.3, whose
/// note says rule 2 is there for this). `vredor.vs` takes and leaves its
/// scalar in element 0 of a single register whatever LMUL is (31.14): the
/// first trip's is element 0 of its own elements, which the OR already
/// covers, so nothing has to be zeroed first, and the later trips' is the
/// mask so far.
///
/// Up to [`SCALAR_ENTRIES`] entries take a scalar loop of five instructions
/// an entry instead, and an empty list (a flush packs the list of every
/// size class, used or not) only a branch: the vector path costs four `m8`
/// instructions, a `vsetvli` and a move out of a vector register whatever
/// the length is. The threshold is a judgement, not a measurement: no
/// riscv64 hardware has run this.
#[inline(always)]
pub(crate) fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  // As the portable form: a length above 64 is a bounds failure.
  let live = &blocks[..usize::from(len)];
  let mask: u64;
  // SAFETY: `live` is a shared borrow of the first `len` entries, so it may
  // be read for `live.len()` bytes (`Cell<u8>` has the layout of `u8`), and
  // the list belongs to the calling thread, so nothing writes it meanwhile.
  // The block reads those bytes and no others. The scalar loop runs for
  // 1 to `SCALAR_ENTRIES` entries, from `p` up to `p + n`, and so ends. The
  // vector trips run until `n` is zero; each `vle8.v` reads the `vl` bytes
  // at `p` and nothing past them (tail elements are not accessed, 31.5.4),
  // `vl` is at most the remaining `n` (31.6.3, 5.d) and above zero while
  // `n` is (5.b), so the loop ends, and `p` advances by `vl`: the bytes
  // read are the first `n`, once each, for any VLEN and any choice of `vl`.
  // No length is read from a register that could be `x0` (operands of
  // class `reg` never are).
  // Elements read are ones written under the same or a longer `vl`: `v8`'s
  // by the two instructions before, `v16`'s under the first trip's `vl`,
  // the longest (31.6.3), and element 0 of `v1` by the first trip, whose
  // `vl` is not zero. The block writes no memory and uses no stack
  // (`readonly`, `nostack`), and its result depends only on its operands
  // and those bytes (`pure`). Registers written: the scalar operands (all
  // `out` or `inout`, so none shares a register with an input that is read
  // later), `v1`, `v2` and the groups `v8`-`v15` and `v16`-`v23`, all
  // declared; `vl` and `vtype` change and `vstart` is left zero, which the
  // absence of `preserves_flags` declares (see the module documentation).
  // The instructions exist because V is this build's baseline, checked
  // before the first allocation of the process and of each thread.
  unsafe {
    core::arch::asm!(
      "li {mask}, 0",
      "beqz {n}, 5f",
      "li {t}, {scalar}",
      "bltu {t}, {n}, 3f",
      // Up to `SCALAR_ENTRIES` entries: `n` becomes the end, `u` is one.
      "add {n}, {p}, {n}",
      "li {u}, 1",
      "2:",
      "lbu {t}, 0({p})",
      "addi {p}, {p}, 1",
      "sll {t}, {u}, {t}",
      "or {mask}, {mask}, {t}",
      "bne {p}, {n}, 2b",
      "j 5f",
      // More entries: `u` of them a trip.
      "3:",
      "vsetvli {u}, {n}, e64, m8, ta, ma",
      "vmv.v.i v16, 1",
      "vle8.v v2, ({p})",
      "vzext.vf8 v8, v2",
      "vsll.vv v8, v16, v8",
      "vredor.vs v1, v8, v8",
      "sub {n}, {n}, {u}",
      "beqz {n}, 6f",
      "4:",
      "add {p}, {p}, {u}",
      "vsetvli {u}, {n}, e64, m8, ta, ma",
      "vle8.v v2, ({p})",
      "vzext.vf8 v8, v2",
      "vsll.vv v8, v16, v8",
      "vredor.vs v1, v8, v1",
      "sub {n}, {n}, {u}",
      "bnez {n}, 4b",
      "6:",
      "vmv.x.s {mask}, v1",
      "5:",
      scalar = const SCALAR_ENTRIES,
      p = inout(reg) live.as_ptr() => _,
      n = inout(reg) live.len() => _,
      mask = out(reg) mask,
      t = out(reg) _,
      u = out(reg) _,
      out("v1") _,
      out("v2") _,
      out("v8") _,
      out("v9") _,
      out("v10") _,
      out("v11") _,
      out("v12") _,
      out("v13") _,
      out("v14") _,
      out("v15") _,
      out("v16") _,
      out("v17") _,
      out("v18") _,
      out("v19") _,
      out("v20") _,
      out("v21") _,
      out("v22") _,
      out("v23") _,
      options(pure, readonly, nostack),
    );
  }
  mask
}

/// The most words [`nonzero_words`] reads with its scalar loop.
const SCALAR_WORDS: usize = 4;

/// The most entries [`pack_blocks`] reads with its scalar loop.
const SCALAR_ENTRIES: usize = 8;
