[English](README.md) | [Deutsch](README_de.md)

# scanner-image — scanner image `ujc-scanner:<YYYY-MM-DD>`

One image with all scanners and the tools for the behavior probe. It is built locally, not pulled
from a registry, and contains no tokens or secrets.

## Building

```bash
tools/setup.sh              # builds when no image matches the current state of this folder
tools/setup.sh --rebuild    # forces a rebuild without cache
# by hand:
docker build --build-arg IMAGE_DATE=$(date +%F) -t ujc-scanner:$(date +%F) tools/scanner-image
```

`setup.sh` computes a hash over this folder (Dockerfile, lock files, `scan_inside.sh`) and writes
it into the image as label `ujc.context`; that is how it recognises whether a rebuild is needed.
The build needs network (Docker's default build network) for the downloads; everything downloaded
is verified (see below). The image is built for `linux/amd64`, size about 2.4 GB.

## Supply chain

| Source | Verification |
|---|---|
| base `python:3.12-slim-bookworm` | pinned by digest (`ARG BASE`) |
| binaries (gitleaks, trufflehog, osv-scanner, trivy, syft, grype, actionlint, hadolint, shellcheck, scorecard) | official GitHub releases, SHA-256 fixed in the Dockerfile; compared with the vendor's checksum file when entered |
| gitleaks default rules (`config/gitleaks.toml` of the tag) | SHA-256 fixed in the Dockerfile |
| Node.js | official tarball from nodejs.org, SHA-256 from `SHASUMS256.txt` |
| Semgrep rules (`semgrep/semgrep-rules`) | fixed commit, integrity via the commit hash; test fixtures removed |
| Python tools | each in its own venv from `lock/<name>.txt` (all dependencies with hash, `--require-hashes`, wheels only) |
| npm tools | `npm/package-lock.json` (integrity hashes), `npm ci --ignore-scripts` |
| Debian packages (git, strace, tcpdump, inotify-tools, procps, ca-certificates) | fixed versions from bookworm |

**Regenerating lock files:** `tools/scanner-image/generate_locks.sh` — runs in throwaway
containers in the internal network via the egress proxy (list `standard`), Python with
`uv pip compile --no-build --generate-hashes` (no build backend of foreign sdists), npm with
`--package-lock-only --ignore-scripts`. Afterwards read the diff, rebuild, update `VERSIONS.md`.

**Raising a version:** change version **and** SHA-256 in the Dockerfile (download the vendor's
checksum file, compare the entry), or change `lock/*.in` and regenerate the locks. If the build
breaks because Debian replaced a package version: enter the new version, do not unpin.

## Tools and their network behaviour

| Tool | purpose | downloads at runtime? |
|---|---|---|
| gitleaks | secrets (working tree and Git history) | no |
| trufflehog | secrets | checks for updates → `scan.sh` sets `--no-update`; verification (`--no-verification` off) would send findings to the provider APIs |
| osv-scanner | vulnerabilities in lockfiles | yes: OSV API (`api.osv.dev`) — sends package name and version, no code |
| trivy | vulnerabilities | yes: database from `mirror.gcr.io` (fallback `ghcr.io`); telemetry and version check off via ENV |
| syft | SBOM | no (update check off via ENV) |
| grype | vulnerabilities on the SBOM | yes: database from `grype.anchore.io`; update check off via ENV |
| semgrep | SAST with local rules (`/opt/semgrep-rules`) | metrics and version check off via ENV; `--config p/...` (registry) would need `semgrep.dev` — not intended |
| bandit, ruff, radon, lizard | Python SAST, lint, complexity | no |
| guarddog | heuristics for malicious packages | **yes**: downloads lists of popular packages at start (github.com, hugovk.github.io, packages.ecosyste.ms); without network it falls back to the bundled lists (warnings only) |
| zizmor | GitHub Actions check | offline (`ZIZMOR_OFFLINE`, `--offline`) |
| actionlint, hadolint, shellcheck | workflows, Dockerfiles, shell scripts | no |
| jscpd | duplicates | no |
| knip | unused JS/TS code | no, but **loads project configurations (`knip.ts`, `vite.config.ts` …) = executes project code** → not in `scan.sh`, only after approval like a behavior probe |
| scorecard | OpenSSF rating of a GitHub repository | needs network and `GITHUB_AUTH_TOKEN` at runtime (`-e GITHUB_AUTH_TOKEN`, token never in the image); not in `scan.sh` |
| snyk-agent-scan (successor of `mcp-scan`) | agent/MCP/skill components | needs `SNYK_TOKEN`, **sends component data to the Snyk API** and starts MCP servers for discovery (= executes foreign code) → not in `scan.sh`, only after approval |
| strace, tcpdump, inotify-tools | behavior probe (`tools/behavior_probe.sh`) | no |

MCP/agent scanners and heuristics (guarddog, snyk-agent-scan) have a high false-positive rate:
they are pointers, not a verdict — every hit is verified against the code.

## In the image

- user `scanner` (uid 10001), work folder `/home/scanner`
- `/opt/ujc/scan_inside.sh` (the flow of `tools/scan.sh` inside the container), `/opt/ujc/gitleaks.toml`
- `/opt/semgrep-rules` (commit in `UJC-COMMIT`), `/opt/ujc-apt-versions.txt`
- `/db` (owner `scanner`): mount point of the volume `ujc-scanner-db` for the trivy/grype DB

Versions of the current build: [`VERSIONS.md`](VERSIONS.md).
