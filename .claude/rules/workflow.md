# Workflow

1. Read the relevant section of `docs/ARCHITECTURE.md` before changing
   behaviour; it carries the reasoning. Read the rule in `docs/REQUIREMENTS.md`
   or KM43 before changing what a rule binds.
2. If a change contradicts a document, one of them is wrong — fix both in the
   same commit. Never leave them disagreeing. A change to what KM43 or the
   hardware repository says goes to that repository; nothing is worked around
   here.
3. Name the failure the change prevents. If you cannot, it may not be needed
   yet.
4. Write the test first when the change is a fix; the test that fails is the
   bug report.
5. A hazard row in `docs/SAFETY.md` that the change touches is updated in the
   same commit, with its evidence column honest.
6. `just check` before committing. One logical change per commit; the message
   says what changed and why it mattered. A commit that moves an image's size
   says by how much.
7. Plans, proposals and research are issues, never files in this repository.
