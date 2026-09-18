# Copilot reviews

For code review, follow `Code Review Rules` in root `AGENTS.md` and the local
instructions that apply to changed files. Read the shared `origin89-review`
skill before reviewing behavior, with its relevant domain skills.

Use shared skills only when they are already available in the review context.
The detailed criteria are maintained in
[engineering's review skill](https://github.com/origin89hq/engineering/blob/main/skills/origin89-review/SKILL.md).
If that skill is unavailable, follow the local review rules and disclose the
missing shared context. Do not install tooling or assume a developer's ignored
cache exists in the hosted review. A link is not evidence that a file was read.

Review the requested head and its callers. Report a reproducible trigger,
consequence, and precise code location. Do not invent findings, duplicate an
existing finding without new evidence, or treat a CI pass as proof of safety.
Leave formatting to the configured linters. Keep review comments concise, with
one physical line per paragraph. A review request authorizes findings, not code
changes or publication.
