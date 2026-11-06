# <name> (UJC build) – usage for developers

<!--
Skeleton for docs/ujc/UJC-USAGE.md in the fork. Forks created before October 2026 keep their old
file name docs/ujc/UJC-EINSATZ.md; do not rename it there.
Audience: developers who USE the tool — short, action-oriented, no patch history (that is in
UJC-PATCHES.md).
Every promise here must be kept by the code; write "best effort" explicitly where it applies.
Lives in the fork (private); the checker holds nothing of it publicly. Remove this comment.
-->

Version `<version>`. Rationale and details: [`UJC-PATCHES.md`](../../UJC-PATCHES.md).

## Credentials – what is promised

**<One sentence, bold: the hard promise, e.g. "Credentials never leave the machine without approval;
local copies are redacted on a best-effort basis.">**

- What never happens without approval.
- What happens with approval and what is redacted in the process — and what is not detected.
- Which local files are copies of the project (do not check them in, do not pass them on).

## For what

One paragraph: purpose, **only** <scope: which repositories>, form of use.
Foreign or cloned repositories (e.g. a folder of reference clones) are **not** worked on.

## Installation

Only by yourself, with a fixed tag, outside any project:

```text
<installation command with @<tag>>
```

Clean up first (if applicable): <uninstall the upstream version, delete caches — semver trap:
`-ujc.N` is a pre-release and LOWER than the upstream version>.
Check afterwards: <how to see that the UJC build is active>.
Removal: <command>.

## Allowed commands / functions

| Command / function | Purpose |
|---|---|

## Approvals (environment variables, only you set them)

| Variable | allows |
|---|---|

Consent in the chat is **not** an approval. Do not set the variables permanently, only for the one
run; for projects with sensitive data only after consultation.

## Locked (aborts with a message)

| Area | Examples |
|---|---|

## Prohibitions (usage policy)

- No foreign, cloned or untrusted repositories.
- No credentials in commands, files, prompts or the chat.
- Do not let anything install itself; do not install the upstream version in parallel.
- Do not rebuild locked functions by hand and do not set opt-in switches to unlock something.
