# Security audit before use — audit brief (shared by Claude and Codex)

<!--
Template for the initial audit (skill tool-review, step 5).
The SAME text goes to the Claude subagent AND to Codex — only then are the two verdicts
comparable. Filled-in version: .claudex-tmp/<name>/audit-brief.md (gitignored), after the run as
raw material into the fork (docs/ujc/audit/brief.md) or summarised in
private/records/<name>/reviews/round-01-….md. Replace the placeholders <…>, remove this comment.
For Codex put the preamble below (section "Codex preamble") IN FRONT OF the brief.
-->

Goal: decide whether `<name>` (<kind: Claude Code plugin / skill / MCP server / CLI /
Python package / npm package>) may be used on developer machines
(<environment of the review: OS, agent tooling, guard hooks, binding global rules, parallel
sessions per repository>). NOTHING is installed. The sources are in
quarantine and are to be checked read-only.

Audited state (only this one, load nothing else):
- `<name>`: `<path of the quarantine clone>` = `<upstream URL>` @ `<full SHA>` = tag `<tag>` (<date>).
  Installation path: `<…>`. What runs at runtime: <manifest, hooks (number/events),
  MCP servers, CLI/entry points, bundled code vs. source>.
- Supply chain already checked: <published package `<pkg>==<ver>` against the tag: identical in content
  except …, after CR normalisation / bundles against src: …>.

Already automated: gitleaks (redacted) — <n> hits (<assessment>); grype — <…>;
hadolint/actionlint — <…>.

## Check points (answer each one explicitly, with file:line)

1. **Network**: every outgoing endpoint (fetch/http/https/net/WebSocket/dns,
   curl/wget/Invoke-WebRequest in shell strings). Telemetry, analytics, error reports,
   auto-update, version queries. WHICH data goes out, can it be switched off, is it
   on by default?
2. **Code execution**: child_process/exec/spawn/subprocess, eval/new Function/exec(), loading
   code at runtime (npx/uvx/pip/npm install, download+execute), shell injection from prompt,
   file or repository content; program lookup via the working directory (Windows!).
3. **Hooks and permissions**: what each hook may do — block, change tool input,
   grant permissions automatically (`PermissionRequest`, `permissionDecision: allow`,
   `updatedInput`, `allowedTools`, `bypassPermissions`, `acceptEdits`,
   `--dangerously-skip-permissions`, sandbox flags of foreign CLIs), inject context. Behaviour
   on errors (fail-open/fail-closed), started processes, run time per tool call.
4. **Credentials**: reading `~/.claude/.credentials.json`, `~/.codex/auth.json`,
   keychain/Credential Manager, environment tokens, MCP configurations; where are they sent,
   mirrored or written to (including temp files, logs, state files)?
5. **File system**: writing outside the project or the plugin's own folder —
   especially `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.claude.json`, `~/.codex/*`,
   other plugins, shell profiles, autostart; deleting; git operations
   (commit/push/`add -A`/reset/deleting branches).
6. **Persistence and self-modification**: self-update, scheduled tasks, services, leftovers after
   uninstallation; what exactly the setup/install command changes (complete list).
7. **Supply chain**: dependencies and pins, install scripts (`postinstall`, build hooks),
   bundled code vs. source (samples whether bundles contain code that does not appear in the
   source, especially network/exec), published package vs. tag.
8. **Prompt injection**: is foreign content (web, files, repository text, tool output) fed into the
   model with tool permissions; skills/agents meant to override security rules or bypass the
   user; rules that override the user's CLAUDE.md or hooks.
9. **Compatibility with the environment**: conflicts with own guards (push lock,
   `git add -A` lock, repository root guard), global rules, multi-session operation,
   Windows particularities (paths, code page cp1252, CRLF, program lookup in the CWD).

## Result format (English)

- Numbered findings, severity CRITICAL / HIGH / MEDIUM / LOW, each with file:line, what
  concretely happens, and one line of remedy.
- Per check point 1–9 one sentence "checked: … / not checked: …".
- Recommended safe configuration (which hooks/functions to switch off, scope global vs.
  project, network).
- Coverage note: which files were NOT opened.
- Last line exactly one of: `VERDICT: USABLE`, `VERDICT: USABLE WITH CONDITIONS`,
  `VERDICT: DO NOT USE`.

Off limits: install nothing, execute nothing that starts code from the package; open no files
outside `<path of the quarantine clone>` except `~/.claude/CLAUDE.md` for comparing the
rules. Do not open: `.env*`, `~/.claude/settings.json`, `~/.claude/.credentials.json`,
`~/.codex/auth.json` or any other real credential file.

## Codex preamble (put in front of the brief)

```text
You are an adversarial security reviewer (read-only). Check EXCLUSIVELY `<name>` under
`<path of the quarantine clone>` according to the following audit brief. Read the code yourself (rg, Get-Content),
do not rely on README statements. For gitignored or hidden bundles always call rg with
`--no-ignore --hidden`. Do NOT open `~/.claude/settings.json`, no `.env*` files, no
credential files. Change no files, execute no code from the package.
```
