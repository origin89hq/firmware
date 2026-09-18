#!/usr/bin/env python3
"""Refuse `git checkout`/`git restore` on a path that has uncommitted changes.

This repo asks you to break a check on purpose and watch it go red, several
times a day. `git checkout -- <file>` is the obvious-looking undo and it is not
an undo: it restores the file to the last commit, so it discards the break *and*
everything else in that file that was not committed yet. The command succeeds,
prints nothing, and leaves a tree that looks tidy.

It has cost re-applied work three times in one session. Nothing warned; the loss
was noticed only because the next command failed to compile.

So the machine says so instead. A branch switch, a checkout of a clean file, and
`git checkout -b` all pass through untouched — the only thing refused is the one
that silently throws work away.

A file that is staged with a clean worktree is refused too, and that one is a
false positive for the `-- <file>` form: it restores from the index, so the
staged change survives. `git checkout HEAD -- <file>` discards it, the two are
four characters apart, and refusing beats evicting.
"""

import json
import os
import re
import shlex
import subprocess
import sys

RESTORING = {"checkout", "restore"}

HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def without_heredocs(command: str) -> str:
    """The command with every heredoc body removed.

    A heredoc body is prose, not shell, and this repo writes commit messages
    that quote the command being guarded against. Left in, the very first
    commit explaining this hook was refused by it — the message said
    `git checkout -- <file>` and named a file that was dirty, which is
    indistinguishable from the real thing once `shlex` has flattened it.
    """
    lines = command.split("\n")
    kept: list[str] = []
    delimiter: str | None = None
    for line in lines:
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        kept.append(line)
        found = HEREDOC.search(line)
        if found:
            delimiter = found.group(2)
    return "\n".join(kept)


SEPARATORS = re.compile(r"&&|\|\||[;|\n]")


def paths_being_restored(command: str) -> list[str]:
    """Arguments to a `git checkout`/`git restore` that name a path on disk.

    A branch name is not a path, so `git checkout main` yields nothing and is
    never in the way.

    **Scanned one statement at a time**, split on `&&`, `||`, `;`, `|` and the
    newline. A path list does not span a statement, and scanning past the end
    of one is what turned a commit message into a refusal: the subject line
    read *Refuse a git checkout that would discard uncommitted work*, which is
    a bare `git checkout` followed by prose, and twenty tokens later the body
    said `CLAUDE.md` — a file that was dirty.
    """
    found: list[str] = []
    for statement in SEPARATORS.split(command):
        try:
            tokens = shlex.split(statement, comments=True)
        except ValueError:
            # An unbalanced quote is not ours to diagnose. Let the shell say so.
            continue
        if not tokens or tokens[0] != "git":
            continue
        # Skip `git -C dir`-style globals to reach the subcommand.
        at = 1
        while at < len(tokens) and tokens[at].startswith("-"):
            at += 2 if tokens[at] in {"-C", "-c"} else 1
        if at >= len(tokens) or tokens[at] not in RESTORING:
            continue
        for arg in tokens[at + 1 :]:
            if arg == "--" or arg.startswith("-"):
                continue
            if os.path.exists(arg):
                found.append(arg)
    return found


def dirty(path: str) -> bool:
    """Whether git has anything uncommitted under `path`."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--", path],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.returncode == 0 and bool(out.stdout.strip())


# The message that was refused by the first version of this hook, reduced to the
# two lines that did it. Both matter and the first is the one that is easy to
# write a weaker case than: the subject has a **bare** `git checkout`, not a
# backticked one, so it tokenises exactly like the real command. The filename
# arrives on a later line.
HEREDOC_COMMIT = """git add -A && git commit -q -F - <<'EOF'
Refuse a git checkout that would discard uncommitted work, and say why

CLAUDE.md gets the rule beside the one that creates the hazard.
EOF
git log --oneline -1"""

# The other half, and it needs a case of its own: statement-splitting cannot
# save this one, because the body line *is* the command exactly. Commit messages
# in this repo quote shell, so a message showing what not to do would otherwise
# be refused for showing it.
HEREDOC_QUOTING_SHELL = """git commit -q -F - <<'EOF'
Do not do this, and here is the thing not to do:

git checkout CLAUDE.md

Restore from the copy instead.
EOF"""

# What the parse must and must not find, run by `--self-test`. Only the parsing
# is here: which paths a command names is where the bug was, and it is the half
# that does not depend on what happens to be dirty today.
CASES: list[tuple[list[str], str]] = [
    ([], "git checkout main"),
    ([], "git checkout -b a-new-branch"),
    ([], "git checkout 3fdc8c3"),
    ([], "git status --porcelain"),
    ([], "cargo test -q && git log --oneline -1"),
    ([], 'echo "never git checkout CLAUDE.md"'),
    ([], HEREDOC_COMMIT),
    ([], HEREDOC_QUOTING_SHELL),
    (["CLAUDE.md"], "git checkout -- CLAUDE.md"),
    (["CLAUDE.md"], "git restore CLAUDE.md"),
    (["CLAUDE.md"], "git checkout HEAD -- CLAUDE.md"),
    (["."], "git checkout -- ."),
    (["CLAUDE.md"], "git -C . checkout CLAUDE.md"),
    (["CLAUDE.md"], "cargo test -q; git checkout CLAUDE.md"),
    (["CLAUDE.md"], HEREDOC_COMMIT + "\ngit checkout CLAUDE.md"),
]


def self_test() -> int:
    """Run the parse against every case. Exit 1 on the first disagreement.

    The heredoc cases are the ones that earned their place: the first commit
    explaining this hook was refused by it, because the message quoted the
    command it guards against and named a file that was dirty.
    """
    wrong = 0
    for want, command in CASES:
        got = paths_being_restored(without_heredocs(command))
        if got != want:
            wrong += 1
            print(f"want {want}, got {got}: {command!r}", file=sys.stderr)
    if wrong:
        print(f"{wrong} of {len(CASES)} cases wrong", file=sys.stderr)
        return 1
    print(f"{len(CASES)} cases, all as expected")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    command = without_heredocs(event.get("tool_input", {}).get("command", ""))
    if "checkout" not in command and "restore" not in command:
        return 0

    losing = [p for p in paths_being_restored(command) if dirty(p)]
    if not losing:
        return 0

    print(
        "Refused: "
        + ", ".join(losing)
        + " has uncommitted changes, and `git checkout`/`git restore` on a path "
        "discards all of them — not only the edit you meant to undo.\n\n"
        "If you are putting back a deliberate break: restore from the copy you "
        "made before it.\n"
        "  cp \"$SCRATCH/<file>.bak\" <file>\n\n"
        "If there is no copy, the edit tools can undo the break precisely. "
        "`git stash` is not the fix either — it moves the whole tree.\n\n"
        "See CLAUDE.md, 'Put it back from a copy, never from git'.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
