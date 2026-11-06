# Final test brief (template)

<!--
Template for final tests and intermediate rechecks (skill tool-review, step 10).
The text under "Brief" goes to Codex as a prompt file:
  python tools/codex_ro.py --model gpt-6-astra --effort medium --prompt-file <file> --out-file <out> --err-file <err>
(from the checker root, so that Codex loads its AGENTS.md; invocation mechanics: AGENTS.md).
Final test = gpt-6-astra/medium, intermediate recheck = gpt-6.1-sol/medium. Higher effort only after
approval by the owner. One run per quota window, one after the other, never in parallel.
Result of the run: private/repos/<name>/reviews/ (own version, not the public record).
Fill it in as plain ASCII text (the prompts in October ran stably that way).
-->

## Brief

```text
You are the final, adversarial security reviewer (read-only) for a hardened fork of <name> (<kind>).
Final test before approval for installation on developer machines (<environment of the review: OS, agent tooling, guard hooks,
binding global rules, parallel sessions per repository>).

Subject: repository `<forks>/ujc-<name>`, state `<sha>` (<version>), base upstream <tag> = <base-sha>.
<What runs at runtime: e.g. hooks.json -> scripts/*.mjs -> dist/, MCP bridge/mcp-server.cjs; patches
in src/ AND by hand in dist/ and the bundles>. Round <N> answers your previous final test (wording:
`<path to the previous round's output>`); check FIRST its findings 1-<n> individually
(FIXED/PARTIAL/OPEN with file:line), THEN the overall state.
CAUTION search tool: rg respects .gitignore and skips hidden folders; built bundles (dist/, bridge/)
and .claude-plugin/.github are otherwise invisible - ALWAYS call `rg` with `--no-ignore --hidden`.
Check with `git diff <base-sha>..<sha>`, rg and direct reading. Do NOT execute package code, install
nothing, change no files.

Criterion: the threat model in `UJC-PATCHES.md`, section "Scope of use and threat model", and
`docs/ujc/UJC-USAGE.md` (older forks: `docs/ujc/UJC-EINSATZ.md`). In summary:
- Use ONLY <scope>. Foreign/cloned repositories are not worked on.
- SWITCHED OFF in the fork (check that the lock applies at EVERY entry point - CLI, library,
  module entries, hooks, skills, keyword triggers, MCP tools - and cannot be switched off): <list>.
- OUTSIDE the model (no obstacle to approval, only check that it is correctly documented as
  outside): <list from the threat model>.
- INSIDE the model, must hold completely:
  1. <requirement 1>
  2. <…>
  N-1. The remaining functions are consistent and plausibly working (syntax, missing functions,
     wrong imports, unreachable paths).
  N. Tests check the requirements in both directions; the docs do not promise more than the code keeps.

Result in English: numbered findings (only INSIDE the model) with severity CRITICAL/HIGH/MEDIUM/LOW,
file:line, concrete trigger, one line of remedy; per requirement 1-N CONFIRMED / REFUTED /
NOT VERIFIABLE; a short list "outside the model, correctly documented yes/no"
<for plugins: list of the hooks and MCP tools still active with a short rating>; coverage note.
Last line exactly one of: `FINAL TEST: APPROVED`, `FINAL TEST: APPROVED WITH CONDITIONS`,
`FINAL TEST: NOT APPROVED`.
Off limits: no `.env*` files, not `~/.claude/settings.json`, no real credential files
(`~/.claude/.credentials.json`, `~/.codex/auth.json`), nothing under folders with third-party data.
```

## Before the run

- [ ] The previous round's output is at a path Codex may read (scratchpad or fork `docs/ujc/audit/`).
- [ ] The fork's working tree is clean, the state committed (Codex checks the commit, not unsaved work).
- [ ] Check the quota (`python tools/codex_usage.py`, if present); no second run in parallel.
- [ ] Bash timeout 600000 ms; output and stderr into files under `.claudex-tmp/<name>/`.

## After the run

- Exit 3 of the wrapper = Codex could not execute any command → the review did not take place,
  do not record it, fix the cause.
- Check the last line (`FINAL TEST: …`); if it is missing, the run is incomplete (abort/timeout).
- Verify every finding yourself in the code before it goes into a patch set.
- Result to `private/repos/<name>/reviews/round-NN-final-test….md` (template `review-round.md`),
  raw material (prompt + output) into the fork under `docs/ujc/audit/`.
