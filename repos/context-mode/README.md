[English](README.md) | [Deutsch](README_de.md)

# context-mode - review summary

| | |
|---|---|
| What | MCP server with hooks that keeps large tool output out of an agent's context and restores session state after compaction |
| Type | Claude Code plugin (also for other agent CLIs) and npm package |
| Upstream | `mksglu/context-mode` - license Elastic-2.0 (source-available) |
| Reviewed version | tag `v1.0.169` = `589d8214d56740a28b5f7bf63167743d586b0b40` |
| Reviewed on | 21.10.2026 |
| Verdict | `DO NOT USE` (Claude and Codex initial audits agree) |
| Recommendation | do not use as shipped |

## Assessment
The idea is sound and addresses a real problem: long tool output wastes context, and a local index with search can
help. The implementation, however, hooks into nearly every tool call, records tool calls and prompts in a local
database, installs dependencies at runtime and can upgrade itself from the default branch of its repository. The
committed bundles were out of date relative to the source, and the marketplace install follows a moving branch, so what
runs is not fixed to a reviewed state. Upstream had no security reporting channel at the time. The license is not an
open-source license.

## Main risks
- Hooks on almost all tool events give the plugin a view of, and influence over, everything the agent does.
- Session records may keep sensitive prompts and command output in a local database.
- Runtime dependency installation and self-upgrade from a moving branch weaken supply chain control.
- Code execution tools in many languages widen what a manipulated agent can run.
- A global hook is written into the user's agent settings.
- No reporting channel exists for security findings, and the dependency set had known gaps.

## Recommendation
Do not use the reviewed version. If the context-saving idea is needed, prefer an approach that pins the installed
version, disables self-update and runtime installation, and limits hooks to the tools it must see. A different
upstream state would need its own review.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
