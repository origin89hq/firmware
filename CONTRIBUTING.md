# Contributing

Follow the [Origin89 engineering standards](https://github.com/origin89hq/engineering)
for working practices, tests, writing and commits. `AGENTS.md` loads the shared
skills at the start of a task; `just skills-sync` refreshes them from
engineering. The rules specific to this repository are in [AGENTS.md](AGENTS.md)
and apply to everyone, not only to an assistant.

## Setup

- just 1.57 or newer and Python 3.9 or newer, for the recipes and the skill
  bootstrap.
- The Rust toolchain in `rust-toolchain.toml`. rustup installs it, with the
  `thumbv6m-none-eabi` and `riscv32imac-unknown-none-elf` targets and
  `llvm-tools`, on first use.
- `espflash` (`cargo install espflash --locked`): the gate measures the comms
  image with `espflash save-image`, and the bench flashes with it.
- For the bench: `probe-rs` for the STM32. A probe attaches to board A through
  a Nucleo's ST-Link; see the board's README in
  [origin89hq/hardware](https://github.com/origin89hq/hardware).

## Before a pull request

`just check` runs everything CI runs: formatting, Clippy with the restriction
lints, the host tests, and `cargo xtask check` — the cross-compiles, the
dependency boundaries and the three images measured against their slots.
`just test-fast` is the inner loop. A change that moves an image's size says
so in its message; `just sizes --record` appends the row to `docs/sizes.tsv`.

A new check in the gate is watched go red before it is trusted: break what it
guards on purpose, see it fail, and put the file back from a copy you made
first — `git checkout -- <file>` and `git restore` discard every uncommitted
change in the file, and a hook refuses them on a dirty path.

A change that can affect physical equipment needs the evidence the
[embedded standard](https://github.com/origin89hq/engineering/blob/main/docs/embedded.md)
asks for: the board revision, the firmware hash, what was measured and with
what. A build is not bench evidence. Flashing and actuation are never part of
an ordinary check.

## Release artifacts

`just reproducible <out>` builds the three images as release artifacts: the
commit at `HEAD` of a clean checkout, staged with nothing else at `/o89` in
the container `xtask/reproducible/Dockerfile` pins, with an empty cargo home
of its own and the `SOURCE_DATE_EPOCH` it requires. Any clean checkout of the
commit, wherever it sits, builds the same bytes (#74); without the fixed
path it cannot, because Cargo hashes the absolute path of every crate under
`crates/` into the symbols. `<out>` holds the `.bin` and ELF of each image
and `manifest.toml`: the commit and tree, the epoch, the environment and
each file's SHA-256. It needs Docker and refuses a dirty checkout, a missing,
zero, malformed or future epoch, and an `<out>` that exists. Ctrl-C stops the
container but leaves the build's scratch directory,
`o89-reproducible-<pid>-<time>` under `$TMPDIR`, to delete by hand.

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) just reproducible ../o89-release
just reproducible-verify ../o89-release
just reproducible-compare ../o89-release ../o89-release-other-checkout
cargo xtask sizes --from ../o89-release --record   # on main, after the merge
```

A release is flashed or published from the recorded files after
`reproducible-verify`, which refuses a directory holding anything but the
three images and their manifest, never rebuilt at another path. `sizes --from --record` takes its row
from such a directory, and only in a clean checkout of the commit it was
built from. Ordinary builds keep their actual build time. The identity is
qualified for one platform at a time; the manifest names the one that built
it.

## Protocol

Wire numbers are allocated in [km43](https://github.com/origin89hq/km43) and
nowhere else. A firmware takes them from the crate; a literal here is a second
opinion that agrees until the registry moves.
