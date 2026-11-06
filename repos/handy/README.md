[English](README.md) | [Deutsch](README_de.md)

# handy - review summary

| | |
|---|---|
| What | Desktop push-to-talk speech-to-text app with local models; the text is pasted into the focused application |
| Type | Tauri 2 desktop application (Rust backend, web frontend) |
| Upstream | `cjpais/Handy` - license MIT |
| Reviewed version | tag `v0.9.8` = `14f6f0d31cb22a4268acfbddba3052820fd0a06e` |
| Reviewed on | 31.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Claude and Codex audits, same verdict) |
| Recommendation | use only with conditions |

## Assessment

The app is small, runs transcription locally, has no server component and no listening port, and no
telemetry was found. Network use is limited to model downloads, a signed update check and an optional,
user-configured language-model provider that is off by default. The findings are mostly defence-in-depth
issues rather than directly exploitable flaws. The most notable ones concern integrity checks on model
downloads, a very permissive web-view configuration, and local storage of every dictation. One reviewer
rated two of the findings higher than the other. Overall the risk is low to moderate.

## Main risks

- Downloaded model files are not always verified against a published checksum; parsers in native code then read them.
- The web view runs with a permissive content policy and broad file access, which would amplify any future script injection.
- Every dictation is stored as audio and text, and the retention setting can be configured to keep data forever.
- Keys for the optional language-model provider are stored in plain text in the settings.
- Output of that provider is pasted unfiltered and, with auto-submit enabled, could trigger an action.
- Build pipeline uses tag-pinned actions and some unverified downloads; dependency advisories exist but appear mostly unreachable on macOS.

## Recommendation

Acceptable for single-user machines with disk encryption. Keep the optional language-model processing
off or local, disable auto-submit and external paste scripts, use the minimum history retention, delete
stored recordings when handing over the machine, and grant only the microphone and accessibility
permissions. Update manually after verifying each download, and download models deliberately once.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
