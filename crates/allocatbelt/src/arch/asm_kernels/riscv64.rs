//! The riscv64 kernels: hand-written assembly for RV64GC with the V
//! extension (RVV 1.0), the riscv64 floor (docs/platform.md). Self-contained:
//! no `crate::` paths, so the benchmark crate can include this file too.
//!
//! Section numbers below are those of the V chapter of the RISC-V
//! unprivileged specification ("V" Standard Extension for Vector
//! Operations, version 1.0).
//!
//! **One vector length for every VLEN.** Both kernels work on at most 64
//! byte elements under `e8, m4`. VLMAX = LMUL * VLEN / SEW (31.3.4.2), which
//! is 64 for the smallest VLEN the V extension allows (128) and larger for
//! every other one, and `vsetvli` sets `vl` to exactly the requested length
//! when that is at most VLMAX (31.6.3, rule 1). So a request of at most 64
//! elements is granted in full on every implementation: there is no
//! strip-mining loop, and the rule that lets an implementation pick any
//! `vl` from `ceil(AVL / 2)` for an AVL between VLMAX and twice VLMAX
//! (rule 2) never applies. Nothing else depends on VLEN: no instruction
//! here reads or writes an element at or past `vl` in memory (31.5.4), and
//! all element indices used are below 64.
//!
//! **Vector state.** The blocks change `vl` and `vtype` and leave `vstart`
//! at zero, as every vector instruction does (31.3.7); `vxrm`, `vxsat` and
//! `fcsr` are not touched. Rust has no operand for `vl` or `vtype`: an
//! `asm!` block may change them (and `vxsat`, `vxrm` and `fflags`) exactly
//! when it does not claim `options(preserves_flags)`, which is how the
//! compiler is told to set up its own vector configuration again after the
//! block instead of assuming the one it had before. The vector registers
//! are clobber-only operands (`out("v8") _`); each block names every
//! register of the `m4` groups it writes, since a tail-agnostic write may
//! change a whole group (31.3.4.3). Nothing is assumed about the vector
//! state on entry: each block starts with `vset{i}vli`. Every `vsetvli`
//! takes its length from an operand of the `reg` class, which never is
//! `x0` (as the length register, `x0` would mean "keep `vl`" or "VLMAX",
//! 31.6.2).
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
  "riscv64 V + Zbb (e8/m4: vmseq + vfirst < len; cpop, vcompress + vrgather)"
} else {
  "riscv64 V (e8/m4: vmseq + vfirst < len; vcompress + vrgather)"
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
