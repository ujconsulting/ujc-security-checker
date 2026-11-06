[English](README.md) | [Deutsch](README_de.md)

# herald-os - review summary

| | |
|---|---|
| What | Desktop shell and Linux image around a local AI agent, with a plugin that lets the agent control apps, files and the screen |
| Type | Electron desktop app, Linux image and installers, Python agent plugin |
| Upstream | `iamlukethedev/Herald-OS` - license MIT |
| Reviewed version | tag `v0.1.0-alpha.3` = `1b3508555224a3040681a64199fe848e5c74349b` |
| Reviewed on | 12.10.2026 |
| Verdict | `DO NOT USE` (Claude initial audit, for use as an add-on to an existing headless agent; no Codex audit) |
| Recommendation | do not use; at most evaluate in a throwaway VM |

## Assessment
Herald OS is an early alpha by a single maintainer with a very high commit rate and a young repository. It has some
thoughtful safeguards, such as permission tiers, a policy file and an audit log for the machine-control tools, and the
upstream project has private vulnerability reporting enabled. However, release artifacts are only accompanied by
checksums, not signatures, and were not compared against the tagged source. The review judged it a poor fit for the
scenario of adding it to an existing headless agent setup. The scanner run found no secrets and a few transitive
dependency advisories.

## Main risks
- The agent plugin can control applications, files and the screen, so a manipulated agent has wide reach.
- Release images and installers are unsigned, which limits verification of what is installed.
- Installer steps depend on downloaded components that are not strictly pinned.
- The project is alpha, maintained by one person and changes very quickly.
- Some dependencies carry known advisories.
- Platform support is incomplete, so behavior on some systems is untested.

## Recommendation
Do not use it on a machine with real data or accounts. Readers who want to try it should do so only in a disposable
virtual machine without real credentials, build from source rather than trusting release artifacts, and wait for a
more mature, signed release before any wider use.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
