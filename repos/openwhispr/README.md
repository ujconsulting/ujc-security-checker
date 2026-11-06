[English](README.md) | [Deutsch](README_de.md)

# openwhispr - review summary

| | |
|---|---|
| What | Desktop dictation app with local and cloud speech engines, notes, meeting recording, connectors, an assistant and an optional vendor cloud account |
| Type | Electron desktop application (Node main process, web renderer) with auto-updater |
| Upstream | `OpenWhispr/openwhispr` - license MIT |
| Reviewed version | tag `v1.11.0` = `b9e9ebefac4b961456c269164a93ddfdd53438b9` |
| Reviewed on | 31.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Claude audit only; Codex audit pending) |
| Recommendation | use only with conditions |

## Assessment

OpenWhispr is a large, fast-moving application with many features. Dictation can run locally or against a
user-chosen compatible endpoint without an account, but the defaults point to the vendor cloud and must be
changed deliberately. The settings and assistant window runs with weakened isolation, a minimal content
policy and a very large number of internal calls with few sender checks, which would make any script
injection serious. No telemetry services were found, and upstream has fixed some earlier problems, but
hardening proposals for the window isolation were not adopted. The update check cannot be disabled, and
there is no single offline switch. Overall the risk is moderate to high for a dictation tool.

## Main risks

- Weak renderer isolation (sandbox and web security off, minimal content policy, many unguarded internal calls).
- A sign-in link handler that accepts a session without a state check, enabling login forgery.
- Missing binary hardening switches and broad macOS entitlements.
- Update checks and vendor connections that remain even with a custom endpoint; no master offline switch.
- A local control bridge and several unauthenticated local helper servers.
- Downloads without hash pinning, plain-text history kept forever by default, and agent tools acting without approval.

## Recommendation

Suitable only for single-user machines and for readers who accept a large attack surface. Verify the
installer and signature before use, avoid signing in, switch every mode to your own endpoint, and turn
off meeting recording, connectors, the assistant and cloud sync. Allow only the needed network
destinations, set history retention to the minimum, and grant only microphone and accessibility
permissions. If the window-isolation findings are unacceptable, prefer a smaller local-only dictation tool.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
