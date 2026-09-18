# Origin89 firmware. `just` on its own lists every recipe.
#
# The build, lint and test recipes arrive with the first crate: there is no
# Cargo workspace yet, and a recipe that runs against nothing is a documented
# command that fails. See README.md for where the repository stands.

default:
    @just --list --unsorted

# Refresh the shared skills once at the start of a task.
skills-sync:
    python3 .origin89/sync-engineering.py
