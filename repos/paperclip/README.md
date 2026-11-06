[English](README.md) | [Deutsch](README_de.md)

# paperclip - review summary

| | |
|---|---|
| What | Self-hosted server with a web UI that orchestrates companies of AI agents with tasks, budgets, approvals and routines |
| Type | npm packages (CLI, server, adapters), TypeScript monorepo, Docker image |
| Upstream | `paperclipai/paperclip` - license MIT |
| Reviewed version | tag `v2026.1005.0` = `467125fafb47a8520856504fecc48d6e32055db1` |
| Reviewed on | 10.10.2026 (Codex audit 12.10.2026) |
| Verdict | `DO NOT USE` (Codex initial audit; Claude initial audit agrees: not usable with its defaults) |
| Recommendation | do not use with default settings |

## Assessment
Paperclip is an ambitious control plane for coordinating many agents, with useful governance ideas such as budgets and
approvals. In the reviewed version, though, agents are permissive by default, the local mode behaves like an implicit
administrator, and plugins can be installed at runtime. The project had a number of published security advisories and
further open reports at the time, and most review findings were already known upstream without a fix. Telemetry and
update checks are on by default. Both reviewers reached the same conclusion.

## Main risks
- Agents run as child processes of the server user and are permissive by default.
- Local mode grants implicit administrator rights that can undermine other host protections.
- Runtime-installed plugins run as code inside the server environment.
- Untrusted content such as email can reach agents that have shell access.
- Several known vulnerabilities were open without upstream fixes.
- Telemetry, announcements and update checks contact external services by default.

## Recommendation
Do not use it on a workstation or with real credentials. At most, evaluate it in a dedicated, isolated guest system with
snapshots, its own network segment, no real secrets and no email integration, after switching to authenticated mode,
turning off permissive defaults and telemetry, and keeping secrets out of the agents' reach.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
