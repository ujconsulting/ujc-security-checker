# <name> UJC round <N> (<trigger: initial audit / final test <model>: NOT APPROVED>)

<!--
Template for the patch specification per round (skill tool-review, step 9).
This file is the BRIEF for whoever applies the patches (the orchestrating session or a subagent).
During the work it lives in .claudex-tmp/<name>/, afterwards as raw material in the fork
(docs/ujc/audit/<name>-roundN.md). Patch rounds are documented only under private/repos/<name>/.
Identifiers per round with their own letter (P, R, S, U, T, V, W, X … or O, T, R3-, R4- …), so that
code comments, UJC-PATCHES.md, tests and review dispositions point to each other unambiguously.
-->

Repository `<forks>/ujc-<name>`, state `<sha>` (`<version>`).
Review report verbatim (read it completely first): `<path>/<output>.txt`.
State according to the report: <n> older findings FIXED, <n> PARTIAL, <n> new findings (<n> CRITICAL/HIGH).
Goal: every requirement of the threat model CONFIRMED.

Confirmed in the code by the orchestrator: finding <n> (`file:line` …), … — name findings that could
not be confirmed here explicitly and give the reason (no patch on a mere claim).

## Principles of this round

- **Close classes, not locations.** For every finding search for the pattern in the whole repository
  (`rg --no-ignore --hidden` — gitignored bundles and hidden folders such as `.claude-plugin` are
  otherwise invisible) and fix it everywhere; at the end, per pattern, the list of all locations.
- **Switch off before hardening**: if an entry point lies outside the scope of use, it is locked
  (the entry point aborts with a message), not hardened.
- **Bundled code**: if `dist/`/bundles run at runtime, then every change in `src/` AND identically
  by hand in `dist/` and in EVERY bundle; search anchors (`UJC-PATCH <identifier>`) in
  `UJC-PATCHES.md`, so that a later container rebuild can be compared against the hand patches.
- **Central helpers** instead of scattered checks (`<package>/_ujc.py`, `src/ujc/scope-gate.ts` …);
  new helper functions with the prefix `_ujc_`/`ujc_`.
- **Tests in both directions** (lock applies / allowed function works) and, where possible,
  **scanner tests** (AST/rg over the source with a mutation check), so that new upstream entry points
  stand out on the next update.
- **The docs do not promise more than the code keeps** — "best effort" means best effort.
- Patches minimal and clearly delimited: they have to be re-applied on every upstream update.

## Dispositions

<ID1> (finding <n>, <SEVERITY>) — **<rule in one sentence>.** <Where (files, functions), what exactly,
which class (search pattern), exceptions, message text>. Regression test: <…>.

<ID2> (finding <n>) — …

Rejected / outside the model: finding <n> — <reason, reference to the threat model>.

## Mandatory checks before the commit (all, result in UJC-PATCHES "Verification status")

- Syntax: Python `ast.parse` of all changed `.py`; JS `node --check` of all hand-edited
  `.js/.cjs/.mjs` (Node is a checking tool here, it does not start package code).
- Character scan of the changed files: CR (`\r`), BOM (`EF BB BF`), U+2028/U+2029 (raw in a
  JS regex/string = syntax error in older engines, finding omc R3-0), bidi control characters
  (U+202A–U+202E, U+2066–U+2069). Expected: none.
- Generator/golden checks of the project, as far as they run without package code.
- `git diff --stat <before>..` against the dispositions: no file without an identifier, no identifier without a file.
- No pytest/npm test/build on the work machine — the container script does that after approval.

## Completing the round

- Version to `<upstream>+ujc.<n>` or `<upstream>-ujc.<n>` (all locations, lock files).
- `UJC-PATCHES.md`: section "Round <N>" (per identifier: problem, change, locations, limits),
  "Verification status", "Open"; update `docs/ujc/UJC-USAGE.md`.
- **One** commit in the fork (English, without AI attribution): `UJC round <N>: <summary>`.
- In the checker: update `private/repos/<name>/implementation/CHANGELOG.md` and `private/repos/<name>/README-own-version.md`.
