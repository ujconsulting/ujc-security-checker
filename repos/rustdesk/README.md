[English](README.md) | [Deutsch](README_de.md)

# rustdesk - review summary

| | |
|---|---|
| What | Open-source remote desktop client and host (screen, keyboard, clipboard, file transfer, terminal, tunnels) |
| Type | Desktop and mobile application, runs as an operating-system service when installed |
| Upstream | `rustdesk/rustdesk` - license AGPL-3.0 |
| Reviewed version | tag `1.5.0` = `fada664df7a294d1d1a9ca3e7cd3637069122f17` |
| Reviewed on | 31.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Claude audit; Codex audit pending) |
| Recommendation | use only with conditions |

## Assessment

RustDesk is a full-featured remote-access program with a Rust core. Connections between peers are
encrypted and signed through a rendezvous server, and the newest version improved the key exchange.
The main weaknesses are in optional or fallback paths and in defaults: a direct-connection mode is
unencrypted, several fallbacks silently degrade security, and by default nearly every permission is
granted to a connecting party. The project has had a long series of reported vulnerabilities this year,
handled outside the usual advisory channels, and no independent audit was found. Overall the risk is
moderate and depends strongly on configuration. The review was static and did not cover every service.

## Main risks

- A direct-connection mode without encryption or host authentication allows takeover by an attacker on the same network.
- Fallbacks to plaintext or to an unverified server key can be accepted by a user clicking through a dialog.
- Permanent passwords are stored as a fast hash and protected by weak brute-force limits.
- Permissive defaults (file transfer, terminal, tunnels, clipboard) and an update check that is on by default and sends a hardware fingerprint.
- The rendezvous server is the root of trust; whoever controls it can intercept sessions.
- The tool is widely abused in remote-access scams, and fake download sites exist.

## Recommendation

Acceptable for people who self-host the server, configure the server key on every client, use long unique
random passwords per machine, and switch off direct IP access, LAN discovery, unneeded permissions and
the update check. With a self-hosted server also neutralise the client's management API path, and never confirm
insecure-connection dialogs. Install only from the official source and verify the download. Do not use a
pre-release build. Do not use it on machines where untrusted parties may initiate the contact.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
