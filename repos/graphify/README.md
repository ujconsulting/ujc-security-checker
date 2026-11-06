[English](README.md) | [Deutsch](README_de.md)

# graphify - review summary

| | |
|---|---|
| What | Builds a queryable knowledge graph of a code repository and makes it available to coding agents |
| Type | Python package with a command line tool, an MCP server and generated skills for many agent platforms |
| Upstream | `Graphify-Labs/graphify` - license Apache-2.0 |
| Reviewed version | tag `v0.9.76` = `0010e25d0d983bc127cef0ee0f7e490bed74e44c` |
| Reviewed on | 04.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Codex initial audit; Claude initial audit in substance the same) |
| Recommendation | use only with conditions |

## Assessment
graphify does what it promises: it parses source code in many languages and builds a graph that agents can query,
which can save a lot of reading. The published package matched the tagged source. The main concerns are about how it
installs itself: by default it changes agent configuration globally, adds hooks and lets skills install further
software. Optional features send document content to an external language model service. The findings are
manageable if the installation scope is restricted. No upstream fix for the open points was found at the time of review.

## Main risks
- The installer writes instructions and hooks into global agent and git configuration by default.
- Skills can trigger a self-installation or update at runtime.
- Optional document and image analysis sends content to external model providers.
- Generated graph output and its instructions are read back by agents and can carry untrusted text.
- A wide set of platform-specific skills enlarges the amount of code that changes agent behavior.

## Recommendation
Acceptable for readers who install it per project instead of globally, review what the installer writes, keep hooks and
self-update off, and use only local analysis for sensitive repositories. Without those conditions the default setup
grants more reach than a code-graph tool needs.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
