# Versions in the scanner image

Build of **2026-10-12**: `ujc-scanner:2026-10-12`, image id
`sha256:757ccc7511dc1309e01701250b824630ba0a1b0f54a4517dfa4201a3ac92d351`, label `ujc.context`
`e9c57fba00d41be7`, `linux/amd64`, 2.41 GB. Built locally (no registry digest); cite the image id
in records. Verified with `docker run --rm --network none ujc-scanner:2026-10-12 <tool> --version`
(step 5 of `tools/setup.sh`).

| Tool | Version | Source | built |
|---|---|---|---|
| base | `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258` (Python 3.12.15) | Docker Hub | yes |
| gitleaks | 8.30.1 (+ default rules of the tag) | GitHub release, SHA-256 | yes |
| trufflehog | 3.99.2 | GitHub release, SHA-256 | yes |
| osv-scanner | 2.6.0 (osv-scalibr 0.5.2) | GitHub release, SHA-256 | yes |
| trivy | 0.75.0 | GitHub release, SHA-256 | yes |
| syft | 1.54.1 | GitHub release, SHA-256 | yes |
| grype | 0.120.1 | GitHub release, SHA-256 | yes |
| actionlint | 1.7.12 | GitHub release, SHA-256 | yes |
| hadolint | 2.15.1 | GitHub release, SHA-256 | yes |
| shellcheck | 0.11.0 | GitHub release, SHA-256 (asset digest, no checksum file) | yes |
| scorecard | 5.5.0 | GitHub release, SHA-256 | yes |
| semgrep | 1.180.0 | PyPI, lock with hashes | yes |
| semgrep-rules | commit `9bbf021d0acffa3095fcffd17b2bc7787eb4796d` (2026-10-08) | GitHub, commit hash | yes |
| guarddog | 3.2.0 (yara-python 4.5.4) | PyPI, lock with hashes | yes |
| bandit | 1.9.4 | PyPI, lock with hashes | yes |
| zizmor | 1.30.1 | PyPI, lock with hashes | yes |
| ruff | 0.17.0 | PyPI, lock with hashes | yes |
| radon | 6.0.1 | PyPI, lock with hashes | yes |
| lizard | 1.24.1 | PyPI, lock with hashes | yes |
| snyk-agent-scan | 0.6.8 (package `mcp-scan` 0.4.3 is now only a redirect to it) | PyPI, lock with hashes | yes |
| Node.js | 24.21.0 (LTS) | nodejs.org tarball, SHA-256 | yes |
| jscpd | 5.4.1 | npm, lock with integrity | yes |
| knip | 6.41.0 | npm, lock with integrity | yes |
| strace | 6.1-0.1 | Debian bookworm | yes |
| tcpdump | 4.99.3-1 | Debian bookworm | yes |
| inotify-tools | 3.22.6.0-4 | Debian bookworm | yes |
| git | 1:2.39.5-0+deb12u3 | Debian bookworm | yes |
| procps | 2:4.0.2-3 | Debian bookworm | yes |
| ca-certificates | 20250419~deb12u1 | Debian bookworm | yes |

Lock files generated with uv 0.13.0 (`generate_locks.sh`): 114 Python packages, 72 npm packages,
all from pypi.org or registry.npmjs.org, all with hash, no npm install scripts.

Further pinned images of the sandbox:

| Image | Digest | purpose |
|---|---|---|
| `ubuntu/squid` | `sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029` | egress proxy |
| `python:3.12-slim-bookworm` | `sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258` | `container_test_python.sh`, `check.sh`, locks |
| `node:24-bookworm-slim` | `sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20` | `container_test_npm.sh`, npm lock |

Note on trivy: according to public reports, releases from the trivy ecosystem were compromised in
spring 2026 (not verified here). The 0.75.0 pinned here is newer; its checksum matches the vendor
file. That protects against transfer errors and files swapped after the fact, not against a
compromised release process — read the project's advisories before changing the version.
