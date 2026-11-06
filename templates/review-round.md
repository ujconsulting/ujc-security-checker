# Round NN — <kind> (<DD.MM.YYYY>)

<!--
Location: private/records/<name>/reviews/round-NN-<kind>.md for rounds about the UPSTREAM tool (initial audits,
upstream research); rounds about the own version (patch rounds, final tests, rechecks, container tests
and behavior probe of the copy) go to private/repos/<name>/reviews/ instead. NN two digits and consecutive across ALL
rounds of the repository (initial audits, final tests, rechecks, upstream research, container tests).
<kind> e.g. initial-audit-claude, initial-audit-codex, upstream-research, final-test, recheck,
final-test-scope, container-test. Keep it short: the raw material is in the fork under
docs/ujc/audit/, here is the summary with the disposition.
No customer names, no secrets, no exploit details (the file is public).
Findings under embargo (reported confidentially upstream, not yet published) do not appear in
this public file at all - no placeholder, no counter, no "withheld"; they go entirely to
private/repos/<name>/ (round notes, notes.md) until the disclosure is published.
-->

| | |
|---|---|
| Repo | `<name>` |
| Kind | initial audit Claude / initial audit Codex / final test / recheck / upstream research / container test |
| Audited state | `<sha>` (`<version>`) — base upstream `<tag>` = `<sha>` |
| Reviewer | Codex `<model>`/`<effort>` (read-only, `tools/codex_ro.py`) · Claude subagent (`<model>`) · … |
| Criterion | full threat model (hostile repository) · narrowed scope of `<date>` (private usage analysis / fork `UJC-PATCHES.md`) |
| Raw material | fork `docs/ujc/audit/<prompt>.txt` → `docs/ujc/audit/<output>.txt` |
| Verdict | `FINAL TEST: NOT APPROVED` · `FINAL TEST: APPROVED WITH CONDITIONS` · `FINAL TEST: APPROVED` · `VERDICT: …` |

## Audit brief (short)

Two to four sentences: what was checked, against which criterion, what explicitly first
(e.g. "findings 1–4 of the previous round individually").

## Result

Recheck of the previous round (only for a final test/recheck):

| Previous finding | Status | Short |
|---|---|---|
| 1 | FIXED / PARTIAL / OPEN | … |

New findings:

| No | Severity | Finding (one line, without exploit recipe) | Location |
|---|---|---|---|
| 1 | CRITICAL / HIGH / MEDIUM / LOW | … | `file:line` |

## Disposition

| Finding | Decision | Implemented in | Reason |
|---|---|---|---|
| 1 | implemented / rejected / outside the model / usage policy / open | round/patch `<identifier>`, commit `<sha>` | … |

Decisions of the owner in this round (with date), e.g. scope narrowed,
criterion made precise.

## Reference

- Follow-up commit in the fork: `<sha>` "<commit title>"
- Patch rationale: fork `UJC-PATCHES.md`, section "<round>"
