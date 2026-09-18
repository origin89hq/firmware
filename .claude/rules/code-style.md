# Code style

The Power of Ten, adapted to embedded Rust, and enforced by the compiler
where the compiler can: the restriction lints in both workspace manifests
turn the first five into build failures outside `#[cfg(test)]`.

1. **No allocation after init.** Domain crates are `#![no_std]` without
   `alloc`, and the gate refuses `alloc::` in their sources. Every collection
   has a named capacity and a written behaviour when full; refusing beats
   evicting. The comms processor's heap serves the radio's blobs and nothing
   of ours.
2. **Every loop has a bound a reader can name**, and every `await` has a
   deadline or a documented liveness argument. A cooperative executor's
   failure mode is one task starving the rest, and it looks exactly like a
   dead controller.
3. **No recursion.**
4. **No `unwrap`, `expect`, `panic!`, `[]` indexing or unchecked arithmetic
   outside tests.** `get`/`get_mut` with an error; `checked_`/`saturating_`
   where overflow is possible. `expect` in a test is encouraged: a fixture
   that cannot be built should fail at the line that broke.
5. **Every return value is used.** `#[must_use]` on every decision, verdict
   and outcome type — a dropped decision is a rule nothing performed, and it
   is silent by construction.
6. **Invariants are asserted at the boundary**, `debug_assert!` inside.
7. **Match our own enums exhaustively.** No `_` arms: adding a variant should
   break every place that has to think about it.
8. **The smallest scope that works.** No `static mut`; peripheral ownership is
   a type handed out once, not a convention.
9. **`unsafe` is denied at every crate root** and opened per item with
   `#[expect(unsafe_code, reason = "...")]` and a `// SAFETY:` line. Two
   places need it: the bootloader's option-byte write and the download
   window's register write. Never `#[allow]`.
10. **Type-state where a rule must hold in an order**: a wrapper that cannot
    give up its payload before its MAC verifies, a challenge that cannot leave
    before its counter is written. A rule in a type is one the compiler
    reviews.

Beyond the ten:

- **Absence is representable.** Never a default that could be mistaken for a
  measurement; a missing probe is not 0.0 °C.
- **Enums over strings.** States, commands and outcomes are enums; identifiers
  and units are newtypes; strings live at text boundaries with a bounded
  capacity.
- **Traits at the seams, enums in the middle.** Traits for what varies by
  target (clock, storage, ports); enum dispatch for closed sets (devices,
  behaviours), because generics monomorphise and flash is a budget.
- **A rule cites its number.** A test named `f_012_...` or `p_004_...` is what
  the gate counts; a `//! cites:` header is a claim by a whole file and is
  reported as the weaker thing it is.
- **`defmt` on the target, `tracing` on the host, never `log`.**
