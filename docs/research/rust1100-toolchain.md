# Rust 1.100 toolchain

The workspace, fuzz manifest, standalone `bench/standard-mimalloc` manifest,
contributor toolchain and every stable CI job require Rust 1.100.0
(released 2026-11-12). The frozen build identity of the application campaign
scripts and the full-system RISC-V guest payload move with it. The safe
`no_std` core is unchanged, and no source file adopts a 1.100 feature in this
step.

## Assembly features by release

The motivation is easier assembly in Rust source for performance work. Most of
the stable inline and naked assembly surface was already available at the
previous 1.99.0 minimum; per the
[release notes](https://github.com/rust-lang/rust/blob/stable/RELEASES.md),
the one assembly-related stabilization new in 1.100.0 is `extern "custom"`.

| Feature | Stable since |
| --- | --- |
| `asm!` and `global_asm!` (x86_64, aarch64, riscv64) | 1.59 |
| `const` operands in inline assembly | 1.82 |
| `asm_goto` (`label` operands) | 1.87 |
| `#[unsafe(naked)]` functions and `naked_asm!` | 1.88 |
| `#[cfg]` on individual assembly template lines and operands (`asm_cfg`) | 1.93 |
| 128-bit integers in x86 vector registers with `asm!`; `global_asm!` sees globally enabled target features | 1.99 |
| `unsafe extern "custom"` functions | 1.100 |

An `extern "custom"` function has an ABI unknown to the compiler and can only
be called from inline assembly
([reference](https://github.com/rust-lang/reference/blob/master/src/items/functions.md)).
It must be `unsafe`, take no parameters and return `()`, so in practice it is
the declared ABI of a naked function. A naked leaf with a private register
convention no longer has to be declared `extern "C"` (or another known ABI) and
risk being called through a signature it does not follow. The existing RVV age
scan keeps its C ABI: it is called as an ordinary function pointer after its
policy and permission recheck, which `extern "custom"` would not allow.

## Other 1.100 changes reviewed for this workspace

- The `Allocator` trait, `Global`, `System` and the `*_in` constructors of
  `Box` and `Vec` are stable. The allocator does not implement or consume them
  in this change; an implementation would be a public API addition with its own
  review.
- The `Rust` ABI on x86 now passes values in SSE registers when the target
  always has them, which includes the x86-64-v3 floor. This can change
  generated code between Rust functions. No timing was collected; a compiler
  comparison follows the method in
  [rust199-modernization.md](rust199-modernization.md#qualification-method),
  and hosted CI or emulated timings are not performance evidence.
- Cargo uses a new layout for intermediate build artifacts. Tools that look
  inside the build directory must not rely on its paths.
- Rust 1.99.1, also included, fixed a miscompilation of FFI `bool` return
  values on x86_64.
- The never type is stable, `Infallible` is an alias of `!`, and never-type
  fallback is `!` on every edition. Lints and tests pass unchanged on 1.100.0.

## Campaign evidence

Application campaign source manifests record `rustc_release`, and the soak and
campaign verifiers accept only the frozen release. New manifests must be built
with 1.100.0. Evidence captured with 1.99.0 is verified with the scripts of its
recorded source revision, and a compiler change is never mixed into an existing
campaign.
