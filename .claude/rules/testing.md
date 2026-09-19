# Testing

- **More lines of test than of code, and the tests are about failure.**
  Three per public function minimum: normal, edge or empty, rejection.
- **Name the failure, not the function**, and cite the rule:
  `f_005_the_rail_is_never_switched_on_after_minutes_off_on_revision_a`,
  never `test_rail`. The gate counts a rule covered only by a test named after
  it that invokes an assertion in its own body: not in a nested `fn`, not in a
  closure handed to an adapter, not in an `async` block nothing awaits. And a
  test wears no `cfg` but `test`; the gate reads what rustc compiled and does
  not evaluate predicates.
- **A check you have not watched fail is not a check.** Break what it guards
  on purpose, see it go red, then put it back — from a `cp` you made first,
  never `git checkout -- <file>` or `git restore`, which discard every
  uncommitted change in the file. A hook refuses them on a dirty path.
- **Earn these where they apply:** known vectors, round trips over every
  length, every single-bit flip, a simulated season, injected faults, and one
  test per behaviour that fails loudly if its fail-safe is deleted.
- **Crash at every step.** Every persistence and command path runs on the
  host with a deterministic step counter behind the storage seam, crashing at
  step *k* for every *k*, asserting the recovery invariant after each.
- **The hostile peer is a harness.** `HostileComms` runs the comms
  processor's own link from `o89-comms-core` for everything it does
  honestly, with a named capability set on top — drop, delay, reorder,
  replay, withhold, stamp, invent a connection, drain slowly, offer a time,
  reboot — and every test declares the capabilities it uses.
- Unit tests live beside the code in `#[cfg(test)]`; season-scale tests and
  fault injection live in `o89-sim`; captured bench exchanges are committed
  fixtures so a driver is a host test.
- `just test-fast` while working; `just check` before every commit, because
  that is what CI runs.
