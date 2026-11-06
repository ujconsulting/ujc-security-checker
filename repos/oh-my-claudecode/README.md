[English](README.md) | [Deutsch](README_de.md)

# oh-my-claudecode - review summary

| | |
|---|---|
| What | Orchestration plugin for Claude Code with specialised agents, skills, keyword triggers, hooks and an MCP server |
| Type | Claude Code plugin with an npm package; built bundles are committed to the repository |
| Upstream | `Yeachan-Heo/oh-my-claudecode` - license MIT |
| Reviewed version | tag `v5.6.1` = `13543f9d6fc1a13a15b68fe5c97baeb3268569e2` |
| Reviewed on | 04.10.2026 |
| Verdict | `DO NOT USE` (Codex initial audit; Claude initial audit verdict line not preserved) |
| Recommendation | do not use as shipped |

## Assessment
The plugin bundles a large set of useful workflow features: planning, review and verification agents, persistent notes
and several autonomous modes. That breadth is also the problem. It registers many hooks on almost every event, ships
large pre-built bundles that were checked only by sampling against the source, and includes an automatic permission
decision that approves some commands more broadly than a user would expect.
Overall the reviewed version gives the plugin more authority over the user's machine than can be justified.

## Main risks
- A permission hook can auto-approve commands based on loose pattern matching.
- Autonomous and team modes can commit or change files broadly without a human check. Launch options can switch off the permission and sandbox controls of other command-line agents, and follow-up sessions can run without the user's global hooks.
- Hooks read and write agent state and settings, including places that may hold credentials.
- Built bundles in the repository are hard to verify against the readable source.
- Global installer and updater behavior changes the user's environment beyond the plugin itself.
- Notifications and status features contact external services.

## Recommendation
Do not use the reviewed version. Readers who want similar workflows should prefer smaller tools with a narrow hook
footprint, or evaluate this one only in an isolated environment with the permission hook and autonomous modes
disabled. A later version would need a fresh review.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
