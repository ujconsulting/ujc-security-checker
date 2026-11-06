[English](README.md) | [Deutsch](README_de.md)

# voicestudio - review summary

| | |
|---|---|
| What | Local-first voice studio: voice cloning, text-to-speech, transcription, dubbing, dictation, with a local API and tool-server interface |
| Type | Desktop application (Electron shell with a Python backend), plus preview mobile apps |
| Upstream | `debpalash/VoiceStudio` - license AGPL-3.0 (model weights have their own licenses) |
| Reviewed version | tag `v0.5.7` = `beeaae08204f0de5f49d4a087ef2b0ea8fecfcb9` |
| Reviewed on | 31.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Claude and Codex audits, same verdict) |
| Recommendation | use only with conditions |

## Assessment

The release artifacts matched the published checksums and the tagged source, and the release process is
reasonably careful. The application is large and young, and it does a lot: it builds a Python runtime on
first start, downloads models and engine components from several sources, and exposes a local API that
has no authentication of its own. Optional features add further reach, such as LAN sharing, helper agents
that start installed coding tools, and opt-in analytics. No directly remote-exploitable flaw was
confirmed, but the attack surface is wide and several hardening measures are missing. Overall the
risk is moderate and rises with every optional feature enabled.

## Main risks

- A local API and tool-server interface without authentication, protected mainly by a loopback restriction.
- Helper agents that launch installed assistant tools with auto-approved edits and network access, fed by logs and diagnostics.
- Missing application hardening (no runtime integrity switches, relaxed library validation, no sandbox).
- Many download sources at runtime, partly through third-party proxies or mirrors, and dependencies of add-on engines that are not hash-locked.
- Renderer-to-system calls without sender checks, and a share feature with a short PIN and no rate limit.
- Licensing: the default model has a non-commercial license, and the license list marks no model as commercial.

## Recommendation

Suitable only for people willing to run a large, fast-moving application with a broad network footprint.
Keep it on a single-user machine, leave sharing, helper agents, analytics and optional engines off,
restrict outbound connections to the sources you accept, and check the model licenses before any
commercial use. Do not expose its local interface to other users or networks. Windows installers were
not code-signed at the time of review.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
