[English](README.md) | [Deutsch](README_de.md)

# mirofish - review summary

| | |
|---|---|
| What | "Swarm intelligence" prediction engine: builds a knowledge graph from uploaded documents, simulates agent discussions with language models and writes a prediction report |
| Type | Web application (Python backend, Vue frontend), shipped as a container image |
| Upstream | `666ghj/MiroFish` - license AGPL-3.0 |
| Reviewed version | tag `v0.1.2` = `985f89f49acbb44ee14d9d680682c741a44eeebe` |
| Reviewed on | 31.10.2026 |
| Verdict | `DO NOT USE` (Claude and Codex audits, same verdict) |
| Recommendation | do not use |

## Assessment

MiroFish is a research-style prototype, not a hardened service, and the maintainers say it is meant for
trusted local use only. The reviewed release exposes its whole interface without any authentication,
allows requests from any origin, ships with debugging features enabled, and returns internal error
details to callers. Several request parameters are used to build file locations without validation, which
allows access to and deletion of data outside the intended area. In addition, every uploaded document is
sent to a mandatory third-party cloud service with no self-hosting option. Most findings were confirmed
as open by the maintainers, and some are by design. The risk is high.

## Main risks

- No authentication or authorization on any route, combined with open cross-origin access and a debug mode.
- Unvalidated identifiers used in file operations, allowing unintended reads, writes and deletions.
- Detailed internal error output returned to clients.
- Mandatory transfer of all uploaded documents to a third-party cloud service; deletion does not reach it.
- Container image running as root with a development server and mutable tags.
- Stored script injection through unescaped model output, and dependencies with many known advisories.

## Recommendation

Do not use this version: it was not built for any environment where an untrusted party can reach it, and
the document-handling model is incompatible with confidential or personal data. Anyone who still
experiments with it should do so on an isolated machine, behind an authenticating proxy, with no
published ports, debug mode off, restricted outbound traffic, and only non-sensitive documents.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
