[English](README.md) | [Deutsch](README_de.md)

# rustdesk-server - review summary

| | |
|---|---|
| What | Self-hostable rendezvous (ID) server and relay for RustDesk clients, open-source edition |
| Type | Rust network daemons, shipped as packages and container image |
| Upstream | `rustdesk/rustdesk-server` - license AGPL-3.0 |
| Reviewed version | tag `1.1.16` = `73523b31cfd25d77dee862e6fc9f5e1fb5e485ef` |
| Reviewed on | 31.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Claude audit; Codex audit pending) |
| Recommendation | use only with conditions |

## Assessment

The server is small and does not forward arbitrary traffic, which limits some abuse paths. End-to-end
encryption is done by the clients, but the ID server signs the keys and is therefore the root of trust.
The reviewed release has several weaknesses that are exposed to the internet by design: partly fixed
reflection and amplification behaviour over UDP, a shared-key option that protects less than it suggests,
and an outdated parsing library on the network path. The packaged defaults run with full privileges and
without hardening. Fixes exist on the development branch but were not part of the release. The risk is
moderate to high if the server is exposed without extra measures.

## Main risks

- Datagram handling that can be abused for reflection and amplification attacks against third parties.
- A key option that is checked only on some request types, so most protocol paths work without it.
- A parsing dependency with a known advisory sits in front of every key check; a remote crash is plausible but was not verified.
- Unhardened default service setup: full privileges, loosely protected key file, an open relay without a key.
- No effective frame-size or pre-login connection limits; the existing registration limits are not sufficient against resource exhaustion.
- A daily outbound call to the vendor with a stable device identifier, and long-lived storage of client addresses.

## Recommendation

Use only if you build from the reviewed source with updated dependencies (or apply the upstream fixes),
generate and protect the key pair beforehand, run the daemons as an unprivileged, hardened service, and
restrict the firewall to the minimum ports with rate limits and outbound filtering. Strong unique
passwords on every target machine remain the real security boundary. A dependency rebuild and generic rate limits
alone are not enough: enforce the key on both daemons, block the unneeded web socket services, add outbound
filtering against reflection, and do not put a local reverse proxy in front. Do not expose the unmodified
release packages directly to the internet.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
