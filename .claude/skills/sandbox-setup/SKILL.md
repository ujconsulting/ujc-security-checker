---
name: sandbox-setup
description: Set up, check, renew and tear down the secure sandbox of the ujc-security-checker on a machine with Docker - via the single entry point tools/setup.sh (Windows - tools/setup.ps1). Covers - prerequisites (Docker Engine/Desktop with Linux containers on amd64, Git Bash or bash >= 4.4, git, ShellCheck; optional coderabbit CLI and gh), the six steps in a fixed order (prerequisites, egress network and Squid proxy, check.sh, build the scanner image ujc-scanner, start the tools in the image, container scripts and base images), the modes --check (status only), --rebuild (proxy and image anew) and --remove (teardown), local settings in private/, failure patterns and how to fix them. Use this skill when - (1) the sandbox is set up on a machine for the first time, (2) the status is to be checked before a scanner run, container test or behavior probe, (3) setup.sh or check.sh reports an error, (4) scanner versions or lock files changed and the image has to be rebuilt, (5) the sandbox is to be removed.
---

# sandbox-setup - one entry point for network, proxy, check and image

Everything runs through **`tools/setup.sh`** from the checker root. The script is idempotent:
what is already right stays; what is missing or does not match the repository state is completed.
No assumptions about a particular agent - it is a normal command-line tool.

```bash
tools/setup.sh --check     # status only, changes nothing; exit 0 = ready
tools/setup.sh             # set up or complete
tools/setup.sh --rebuild   # recreate the proxy, rebuild the image without cache
tools/setup.sh --remove    # teardown
```

Windows PowerShell: `.\tools\setup.ps1 <same options>` - looks for Git Bash (or `UJC_BASH`) and
passes through; the WSL `bash.exe` is rejected.

What the environment protects and why: `tools/egress/README.md`, skill `docker-sandbox`.

## Prerequisites

| What | At least | Checked by step 1 |
|---|---|---|
| Docker Engine or Docker Desktop, **Linux containers**, architecture **amd64** | Engine 28 - isolated gateway of the sandbox network (measured with 29.8) | yes, abort if the daemon is missing or the platform is wrong |
| bash | 4.4 (Git Bash on Windows; measured 5.2) - empty option arrays under `set -u`; macOS ships 3.2, install a current one (`brew install bash`) | yes |
| git | any recent version (measured 2.51) | yes |
| ShellCheck | 0.11 (measured 0.11.0); `winget install koalaman.shellcheck`, `apt install shellcheck`, `brew install shellcheck` | yes, abort if missing; step 6 runs it |
| network to Docker Hub, GitHub, PyPI, npm, nodejs.org | - | indirectly (build) |
| disk space | about 3 GB image + 1 GB base images + up to 4 GB DB volume | no |
| coderabbit CLI | optional, only `tools/cr_full_review.sh` (measured 0.7.5) | note |
| gh (GitHub CLI) | optional, only the visibility check in `cr_full_review.sh` | note |

Apart from ShellCheck (lint of this repository's own scripts), **nothing** is installed on the
host: all scanners live in the image. Python on the host is not
needed.

## The steps (fixed order, abort at the first error)

| # | Step | what happens | command behind it |
|---|---|---|---|
| 1 | prerequisites | Docker reachable, platform, bash, git, ShellCheck; optional tools; `private/*.conf` read? | - |
| 2 | egress | internal network `ujc-sandbox-net` (`--internal`), proxy `ujc-sandbox-proxy` (Squid, by digest), list `standard` active | `tools/egress/setup.sh [--rebuild] standard` |
| 3 | check | 7 checks in both directions; **not green -> abort**, nothing further | `tools/egress/check.sh` |
| 4 | image | hash over `tools/scanner-image/` -> is there a matching `ujc-scanner:<date>` with the label `ujc.context`? otherwise build (log `$TEMP/ujc-scanner-build.txt`) | `docker build ... -t ujc-scanner:<date> tools/scanner-image` |
| 5 | tools | start every tool once without network, show the version | `docker run --rm --network none ujc-scanner:<date> <tool> --version` |
| 6 | scripts | `bash -n` and `shellcheck -x -S warning` of all scripts and git hooks (any finding = error); base images present by digest, otherwise pull | `docker pull <image>@sha256:...` |

`--check` runs the same steps read-only: step 2 reports network, proxy, active list and whether
the proxy uses the pinned image; step 3 runs (starts only a throwaway container); step 4 reports
whether a matching image exists; step 6 pulls nothing.

Run time: first setup with build a few minutes (downloads ~1 GB); afterwards seconds. An agent's
control script may have a time limit - start the first run as a background process and redirect
the output to a file.

## Local settings (optional, `private/`, gitignored)

Lines `UJC_<NAME>=<value>`, nothing is executed as code; environment variables that are set take
precedence.

| File | Variable | Effect |
|---|---|---|
| `private/egress.conf` | `UJC_EGRESS_LAN_TARGET=<ip>:<port>` | a real service in the own LAN for the negative test; without an entry `check.sh` generically checks the gateway of the Docker bridge network and says so |
| `private/environment.conf` | `UJC_PROTECTED_PATHS=<path>;<path>` | folders under which the scripts never create work directories |
| `private/environment.conf` | `UJC_BASH=<path>` | Git Bash for `setup.ps1` |

Further operation-specific details (hosts, networks): if present, read `private/infra.md`.

## Failure patterns

| Message | Cause | Fix |
|---|---|---|
| Docker daemon not reachable | Docker Desktop not started / service off | start it, `docker info` must answer |
| image is built for linux/amd64 | Windows container mode or ARM machine | switch to Linux containers; ARM: adapt the Dockerfile assets (not planned) |
| `check.sh` not passed, package source `URLError` | the proxy currently has another list active (parallel scan) or the host has no internet | `cat $TEMP/ujc-egress-state/list.txt`; wait for running sandbox containers; `tools/egress/setup.sh standard` |
| `check.sh`: LAN or host **reachable** | network not `--internal`, proxy rules changed | **start nothing**; `tools/setup.sh --rebuild`; if it stays: check `squid.conf` and the network |
| `check.sh`: direct exit connected | the container is attached to a network with a route after all | as above - aborting is correct |
| proxy `ujc-sandbox-proxy` not running | Docker restarted, proxy stopped | `tools/setup.sh` (restarts it) |
| `setup.sh` exit 4, containers still attached to the network | list switch while other sandbox containers are running | wait for their run to finish |
| `squid -k reconfigure` fails | proxy from an older version | `tools/setup.sh --rebuild` |
| `docker build` failed with `sha256sum: WARNING ... did NOT match` | a download differs from the recorded checksum | do **not** adjust the checksum - check the vendor page; possible supply-chain incident, report it |
| `docker build` fails at `apt-get install ...=<version>` | Debian replaced the package version (security update) | enter the new version (`apt-cache policy` in the base image), do not unpin |
| a tool in step 5 does not start | build incomplete, link missing | `tools/setup.sh --rebuild`; otherwise leave the tool out and report it |
| `setup.ps1`: Git Bash not found | Git for Windows missing or in another place | install Git for Windows or set `UJC_BASH` |

The exact wording of the messages is in the scripts; they are ASCII only.

## Teardown (`--remove`)

Aborts as long as sandbox containers are attached to the network. Then removes **only by name**:
proxy container `ujc-sandbox-proxy`, network `ujc-sandbox-net`, all images `ujc-scanner:*`,
volume `ujc-scanner-db` (trivy/grype databases), state folder `$TEMP/ujc-egress-state`. Kept on
purpose: proxy logs (evidence), base images (python, node, squid), result folders under
`$TEMP/ujc-*`. No `prune` over the whole engine. Rebuild: `tools/setup.sh`.

## After changes

| changed | then |
|---|---|
| `tools/egress/squid.conf` | `tools/setup.sh --rebuild` (proxy anew) |
| `tools/egress/allowlist*.txt` | nothing - read on the next `setup.sh`; reason in the commit |
| version or SHA-256 in the Dockerfile, `scan_inside.sh` | `tools/setup.sh` (detects the new context and builds), then update `tools/scanner-image/VERSIONS.md` |
| `lock/*.in`, `npm/package.json` | `tools/scanner-image/generate_locks.sh`, read the diff, then `tools/setup.sh` |
