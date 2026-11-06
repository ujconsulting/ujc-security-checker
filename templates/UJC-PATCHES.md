# UJC patches for <name>

<!--
Skeleton for the fork (root of the fork repository, file UJC-PATCHES.md).
This file is the rationale for EVERY deviation from upstream
and the guide for the next upstream update. It describes what the code does — and, at the marked
places, explicitly what it does NOT do. Lives in the fork (private); the checker holds nothing of it publicly (own-version material:
private/repos/<name>/). Remove this comment.
-->

This fork (`<owner>/<name>-ujc`, private) is <name> by <upstream owner> with a delimited patch
set by ujconsulting. It is built for **one** use (section "Scope of use and threat model"). Anything
beyond that is **locked** at the entry point, not merely discouraged. Summary for developers:
[`docs/ujc/UJC-USAGE.md`](docs/ujc/UJC-USAGE.md).

| | |
|---|---|
| Base | upstream `<owner>/<repo>`, tag `<tag>` (commit `<sha>`) |
| State | `<upstream>+ujc.<n>` (PEP 440) or `<upstream>-ujc.<n>` (semver) — round <n> |
| License | `<license>`, license files unchanged. Change notice: the files named below were changed by ujconsulting (e.g. Apache-2.0 §4b); every location carries `UJC …` comments (`git grep -n "UJC"`) |
| Basis | initial audit Claude + Codex (`docs/ujc/audit/`), final tests per round; review record in the checker (local, `private/records/<name>/`) |

**What this file proves — and what it does not.** <Checked statically / tests in the container on … /
no tests>. Skill texts are instructions to the model, not a technical lock.

## Scope of use and threat model

<from templates/threat-model.md, filled in; decisions with date>

**What the fork is meant for** — …

**What must hold inside the model** (table promise → how implemented, identifiers) — …

**What the fork is not meant for (usage policy instead of code)** — …

## Important: what runs at runtime

<Only for bundled code: source vs. dist/bundles, hand patches twice, search anchors,
what is regenerated on a rebuild (source maps, generated inventories, CI hashes).>

## Approval/opt-in switches (all OFF by default)

| Variable | allows | Identifier | effective? |
|---|---|---|---|

## Round 1 (initial audit, state `<sha>`)

### <ID1> – <rule>

Problem (finding, file:line in upstream) · change · locations · limits.

### Tests (round 1)

## Round <n> (final test `<sha>` "<VERDICT>", findings …)

…

## Adopted upstream PRs

| PR | Title | Files | Merge / note | Upstream status (date) |
|---|---|---|---|---|

At the next upstream release, check whether merged; then discard the fork's own version.

## Verification status

Per round: what was checked statically (ast.parse, node --check, character scan, generator), what ran
in tests (container script, date, result) and what is **not** proven.

## Open

- <deliberately unsolved items, each with identifier and reason>

## Update procedure (new upstream state)

1. `git fetch upstream --tags`, choose the target tag.
2. **Review the upstream diff `<old>..<new>` for security** (new network targets, installation commands,
   hooks, process starts, writes to global files, new entry points of the locked families).
3. New branch from the upstream tag, re-apply the patches at the `UJC` anchors (source AND bundles).
4. Run the scanner tests (in the container) — they report new, unlocked entry points.
5. Rebuild/tests in the container (`tools/container_test_*.sh` in the checker), compare bundles against the hand patches.
6. Final test (`gpt-6-astra`/medium) against the unchanged threat model.
7. Set and tag the version `<upstream>+ujc.<n>` / `-ujc.<n>`; push to the private repository by the owner.

## Installation

Only by the user, with a fixed tag: `<command>`.
