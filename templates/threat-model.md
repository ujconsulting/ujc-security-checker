# <name> — scope of use and threat model

<!--
Template for step 8 of the skill tool-review (decision of the owner).
The filled-in version belongs in the fork (UJC-PATCHES.md, section "Scope of use and threat model",
raw version docs/ujc/audit/<scope-file>.md) and as a summary in private/repos/<name>/README-own-version.md. It is the
criterion of every final test — the final test brief quotes it.

LESSON: settle it as early as possible. Until the scope was narrowed, every final test ran against a
"hostile repository" (every scanned folder prepared); each round closed one layer, and the next
review found the next one. First narrow the scope and SWITCH OFF what is not needed, then harden.
-->

Decision of the owner of <DD.MM.YYYY>.

## What the tool is used for

- Only on <scope: which repositories and data classes> — trusted content, possibly with
  sensitive data (business documents, database schemas).
- Form of use: <e.g. project scope only / only as a Claude Code plugin from a private marketplace /
  only the CLI in the user's own terminal>.
- Allowed functions: <list>.

## Inside the model — must hold completely

1. **No outflow of project content** to cloud services (model APIs, foreign CLIs, webhooks,
   telemetry) without explicit approval via the environment variable `<TOOL>_ALLOW_…=1`. Consent
   in the chat is not an approval.
2. **No unrequested change of global configuration** (`~/.claude/CLAUDE.md`, `settings.json`,
   `~/.claude.json`, `~/.codex/*`, other agent files, plugin cache, shell profiles, scheduled
   tasks) and **no loss of foreign content** in project files (`CLAUDE.md`, `AGENTS.md`).
3. **No automatic permission grants**, no sandbox/bypass flags, **no git actions** behind the
   user's back (`add -A`, commit, push, reset, deleting branches).
4. **Credentials** (realistic criterion): they never leave the machine without approval; what the
   tool itself sends to a model is additionally redacted; local, automatically stored copies are
   copies of the project (gitignored) and are redacted on a **best-effort** basis — complete secret
   detection is not required, and the docs must say so honestly. No credentials are written,
   mirrored or stored in configurations.
5. **No self-installation**, no loading from PyPI/npm, no self-update.
6. The user's **guards and rules** (global CLAUDE.md, hooks, `permissions.deny`) stay effective;
   nothing skips them (e.g. `--safe-mode`, `--bare`, own `--setting-sources`).
7. The shipped code **works** (no syntax errors, no dead entry points).
8. Tests check 1–6 **in both directions** (lock applies / allowed function works); the docs do not
   promise more than the code keeps.

## Outside the model — usage policy instead of code

- Foreign, cloned or otherwise untrusted repositories (e.g. a folder of reference clones) are
  **not** worked on. Prepared programs (`git.exe`) or an activated venv in the repository,
  symlinks/junctions in output folders, malicious folder names and swap races count as outside;
  existing protections stay but are not extended further.
- Direct calls of private helper functions (underscore names, deeper internal functions) by
  foreign code — public entry points and the CLI stay fully inside the model.
- Documented network functions started explicitly by the user with a command of their own
  (`<list>`), provided they are listed in the usage policy (`UJC-USAGE.md`).
- <further items, explicitly decided>

## Reduced attack surface — switched off in the fork

Switching off means: the entry point aborts with a clear ASCII message (not just opt-in, not just
docs), at **every** entry point — CLI, library function, hook, skill, keyword trigger,
MCP tool, module entry (`python -m …`).

| Family | Entry points | Message |
|---|---|---|
| <e.g. global installation> | <…> | `<ujc_scope_disabled: …>` |

## Procedure from here

1. One implementation round "scope": switch off instead of hardening; close open in-scope findings.
2. Then **one** final test against exactly this scope (`gpt-6-astra`, effort **medium**).
3. On approval: report + decision paper (push, container tests, installation).
