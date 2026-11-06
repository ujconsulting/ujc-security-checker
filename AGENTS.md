# ujc-security-checker - operating instructions for Codex CLI

Review station for external tools (GitHub repositories, Claude Code plugins,
skills, MCP servers, CLI tools, Python and npm packages) before they are used on developer
machines. Review scenario: a developer machine (Windows 11) with Claude Code and Codex CLI, guard
hooks, binding global rules and several parallel sessions per repository.
**If present, read `private/AGENTS.private.md`** - it adds the operator's concrete context
(machines, locations, project landscape), which is not part of this public repository.

Codex counterpart of `CLAUDE.md`. This repository is public: no internal details (local paths, LAN
addresses, internal host names, non-public own projects or customers) in versioned files; a
reference to an own repository is allowed only if that repository is public.

## Skills under Codex

Codex finds the project skills under `.agents/skills/<name>/SKILL.md`. They are generated from
`.claude/skills/` by `python tools/codex_skills_sync.py` (`--check` = exit 0 if the mirror is
current) and point to the full text in `.claude/skills/<name>/SKILL.md` - read that one and
follow it. Skills: `tool-review`, `usage-analysis`, `finding-disclosure`,
`mcp-build`, `sandbox-setup`, `docker-sandbox`, `proxmox-lxc-sandbox`.

## Rules that Claude-only mechanisms enforce - they apply to Codex too

Hooks, the guard and `.claude/settings.json` (permissions) do **not** run under Codex. Their
rules still apply and are therefore restated here:

- **No push to GitHub** (checker or forks) without an explicit request by the owner; no PR
  creation, no merge.
- **No `git add -A`, `git add .`, `git add -u`, `git commit -a`** - stage paths explicitly and
  read `git status` before every commit: several sessions work in parallel, foreign work stays
  where it is. One commit per unit of work, without AI attribution.
- **Public/private gate:** `python tools/public_check.py` must exit 0 before every commit
  (`--history` before a push); the git hooks in `.githooks/` run it only if
  `core.hooksPath` points there. Files are English; German only in `*_de.md`; every
  `README.md` has a `README_de.md` with a current source hash (`--stamp`).
- **Approval before any external effect**: nothing that leaves the machine or changes something
  outside the repository (issue, comment, label, advisory, mail, push, scheduled task, global
  configuration, installation) without an explicit instruction by the owner.
- **Disclosures only via the disclosure tools and their approval flow**
  (`tools/disclosures/approval.py`, then `issue_submit.py` / `advisory_submit.py` /
  `mail_report.py send`; dry run first). Never `gh api -X POST/PATCH` or `gh issue create|comment`
  by hand.
- **Install or execute nothing from reviewed repositories** (`pip/uv/npm install`, `uv sync`,
  `npm ci`, `npx`, `uvx`, build, test, import, script). Static tools that start no package code
  are allowed.
- **Sandbox only via `ujc-sandbox-net`**: sandbox containers never in the default bridge network,
  never `--network host`; installation only in the internal network `ujc-sandbox-net` via the
  egress proxy `ujc-sandbox-proxy:3128` after `tools/egress/check.sh` has passed, then disconnect
  the network completely and verify it. Container runs only after approval and only via the
  scripts in `tools/`.

## Role: security reviewer (read-only)

You are called in these forms; the prompt says which:

| Form | Object | Model | Result line |
|---|---|---|---|
| **Initial audit** | quarantine clone `quarantine/<name>/` on a fixed commit | `gpt-6-sol`/medium | `VERDICT: ...` |
| **Final test** | hardened fork `<forks>/ujc-<name>` on a fixed commit (path in the prompt) | `gpt-6-astra`/medium | `FINAL TEST: ...` |
| **Recheck** (intermediate review) | like the final test | `gpt-6-sol`/medium | `FINAL TEST: ...` |
| **Disclosure cross-check** | outgoing disclosure text in the prompt + quarantine clone on the cited commit | from `.env`, default `gpt-6.1-sol`/medium | `CHECK: ...` |
| **Finding validation** | finding fields + outgoing text in the prompt + quarantine clone on the cited commit | from `.env` / claudex-loop role, default `gpt-6.1-sol`/medium | `FINDING: ...` |
| **Exposure pass** | finding fields + outgoing text in the prompt + quarantine clone on the cited commit | from `.env` / claudex-loop role, default `gpt-6.1-sol`/medium | `EXPOSURE: ...` |

Principles:

- **Read the code yourself** (`rg`, `git diff`, `git show`, `Get-Content`); do not rely on README
  or comment statements. A claim in the fork ("round N fixes X") is to be checked, not believed.
- **Always search forks and bundles with `rg --no-ignore --hidden`.** Otherwise `rg` respects
  `.gitignore` and skips hidden folders - built bundles (`dist/`, `bridge/*.cjs`) and
  `.claude-plugin/`, `.github/` would be invisible, although exactly they run at runtime
  (finding of October 2026).
- **Execute nothing that starts package code**: no import, no script, no test, no build, no
  installation. Reading, searching and `git` are allowed. You do not change files.
- **Classes instead of locations**: when you name a finding, search the pattern in the whole
  repository and name all locations, or say explicitly that you did not search completely.
- **In final tests first the findings of the previous round one by one** (FIXED / PARTIAL / OPEN,
  with file:line), then the overall state.
- **Threat model**: it is authoritative in the fork in `UJC-PATCHES.md`, section "Scope of use and
  threat model", and in `docs/ujc/UJC-USAGE.md` (older forks: `docs/ujc/UJC-EINSATZ.md`).
  Findings **outside** the model are no obstacle to release - only check that they are correctly
  documented there as outside. The history per repository: `repos/<name>/README.md` (public
  summary) and `private/records/<name>/reviews/` (local rounds).

## Review catalogue (initial audit: answer every item explicitly, with file:line)

1. **Network** - every outgoing endpoint (fetch/http/https/net/WebSocket/dns,
   curl/wget/Invoke-WebRequest in shell strings); telemetry, analytics, error reports,
   auto-update, version checks. Which data goes out, can it be switched off, is it on by default?
2. **Code execution** - child_process/exec/spawn/subprocess, eval/new Function/exec(), loading
   code at runtime (npx/uvx/pip/npm install, download + execute), shell injection from prompt,
   file or repository content, program lookup via the working directory (Windows searches the CWD).
3. **Hooks and permissions** - what each hook may do: block, change tool input
   (`updatedInput`), grant permissions automatically (`PermissionRequest`, `permissionDecision:
   allow`, `allowedTools`, `bypassPermissions`, `acceptEdits`, `--dangerously-skip-permissions`,
   sandbox/trust flags of other CLIs), inject context; fail-open/fail-closed, started processes,
   run time per tool call.
4. **Credentials** - reading `~/.claude/.credentials.json`, `~/.codex/auth.json`,
   keychain/Credential Manager, environment tokens, MCP configurations; sending, mirroring,
   storing in temp files, logs, state or memory files.
5. **File system** - writing outside the project or the own plugin folder
   (`~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.claude.json`, `~/.codex/*`, other
   plugins, plugin cache, shell profiles, autostart); deleting; git operations
   (commit, push, `add -A`, reset, deleting branches).
6. **Persistence and self-modification** - self-update, scheduled tasks, services, leftovers after
   uninstalling; complete list of what setup/install changes.
7. **Supply chain** - dependencies and pins, install scripts, bundled code vs. source (code in
   bundles that is missing in the source, especially network/exec), published package vs. tag.
8. **Prompt injection** - foreign content (web, files, repository text, tool output) with tool
   permissions in the model; skills/agents that override security rules, bypass the user or
   override the user's CLAUDE.md/hooks (`--safe-mode`, `--bare`, `--setting-sources`).
9. **Compatibility with the environment** - conflicts with the guards (push lock, `git add -A`
   lock, repository-root watcher), multi-session operation, Windows (paths, code page cp1252,
   CRLF/BOM, characters such as U+2028 in shipped JS).

In final tests the list of requirements from the prompt (from the threat model) replaces the
catalogue; the nine items remain the search space.

## Result format (English)

- Findings numbered, severity **CRITICAL / HIGH / MEDIUM / LOW**, each with `file:line`, concrete
  trigger, one line of remedy. No executable exploit recipes.
- Initial audit: per review item 1-9 "checked: ... / not checked: ..."; recommended secure
  configuration.
- Final test: per requirement **CONFIRMED / REFUTED / NOT VERIFIABLE**; list "outside the model,
  correctly documented yes/no"; for plugins the hooks and MCP tools still active with a short
  assessment.
- **Coverage note**: what you did NOT open.
- Last line exactly one of:
  - initial audit: `VERDICT: USABLE` · `VERDICT: USABLE WITH CONDITIONS` · `VERDICT: DO NOT USE`
  - final test/recheck: `FINAL TEST: APPROVED` · `FINAL TEST: APPROVED WITH CONDITIONS` · `FINAL TEST: NOT APPROVED`
  - disclosure cross-check: `CHECK: CONFIRMED` · `CHECK: CORRECTIONS NEEDED`
  - finding validation: `FINDING: CONFIRMED` · `FINDING: NOT CONFIRMED` · `FINDING: SEVERITY WRONG`
  - exposure pass: `EXPOSURE: UNSAFE` · `EXPOSURE: SAFE`
- **Disclosure cross-check is not an audit**: verify only the claims in the given text (table
  claim / location / CONFIRMED-WRONG-OVERSTATED-NOT VERIFIABLE, corrected wording for every WRONG or
  OVERSTATED item); do not look for or report new findings. Prompt built by
  `tools/disclosures/codex_check.py`.
- **Finding validation is not an audit either**: decide only whether the one given finding is real at
  the cited commit (open the code; preconditions, severity class and rating supported; by design per
  the policy fields in the prompt?). Say what you opened; do not report other findings. Last line
  `FINDING: CONFIRMED`, `FINDING: NOT CONFIRMED` or `FINDING: SEVERITY WRONG` (with the rating you
  consider supported).
- **Exposure pass**: decide whether the affected code is reachable from outside the machine (network
  listener, webhook, untrusted input from another party) and by whom; name the entry point and the
  files you opened. Last line `EXPOSURE: UNSAFE` (reachable) or `EXPOSURE: SAFE`. No new findings.

## ⛔ Off limits - do not open

- `.env`, `.env.*`, `*.env` - in every repository
- `~/.claude/settings.json`, `~/.claude/.credentials.json`, `~/.claude.json`, `~/.codex/auth.json`
  and every other real credential file (keystores, `*.pem`, `id_*`, vault exports)
- customer folders of other projects (customers, prospects, customer SQL schemas, shared document
  folders; the concrete folder names are listed in `private/AGENTS.private.md`)
- under `private/` only `private/AGENTS.private.md` and files the prompt names explicitly
- You may read `~/.claude/CLAUDE.md` to compare the rules.

Everything you read goes to OpenAI - hence this list.

## Calling conventions

```bash
python tools/codex_ro.py --model gpt-6-astra --effort medium \
    --prompt-file .claudex-tmp/<name>/final-test-NN.txt \
    --out-file .claudex-tmp/<name>/final-test-NN-out.txt \
    --err-file .claudex-tmp/<name>/final-test-NN-err.txt
```

From the checker root (that is how this file is loaded). The wrapper enforces read-only; never
call `codex exec` directly. Bash timeout 600000 ms. **Exit 3** = Codex could not execute any
command (Windows sandbox) - the review did not happen, do not record it. One run per quota
window, never in parallel. Full operating manual of the wrapper: [claudex-loop](https://github.com/ujconsulting/claudex-loop); operator notes: if present, `private/AGENTS.private.md`.

## Layout

```text
repos/<name>/README.md          public summary of the upstream review (also README_de.md): pinned version, verdict, recommendation
private/records/<name>/         local record of the upstream review (gitignored): reviews/ (one file per round: short
                                audit brief, result, disposition), disclosures/ (drafts, register, policy evidence)
private/repos/<name>/           own version (fork/copy): README-own-version.md, reviews/ (patch rounds,
                                final tests, rechecks, container tests), implementation/CHANGELOG.md;
                                usage analysis, critical drafts (private, gitignored)
templates/                      audit brief, threat model, patch set, final test, fork skeletons, drafts
tools/                          container test scripts, scanners, disclosure tools, codex_ro.py
quarantine/<name>/              quarantine clones (gitignored)
```
