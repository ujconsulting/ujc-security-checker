[English](README.md) | [Deutsch](README_de.md)

# tools — usage

All scripts are plain command-line tools (Bash; on Windows Git Bash, on Linux/macOS
bash ≥ 4) and do not assume a particular agent. Output is ASCII only.

| File | Purpose | executes foreign code? |
|---|---|---|
| `setup.sh` / `setup.ps1` | **one entry point** for the whole sandbox: egress network, proxy, check, scanner image, self-test; `--check`, `--rebuild`, `--remove` | no |
| `egress/` | internal network + Squid proxy with allowlist, `check.sh` (docs: [`egress/README.md`](egress/README.md)) | no |
| `scanner-image/` | scanner image `ujc-scanner:<date>` with all scanners (docs: [`scanner-image/README.md`](scanner-image/README.md), versions: [`VERSIONS.md`](scanner-image/VERSIONS.md)) | no |
| `quarantine_clone.py` | quarantine clone from `owner/name`, `<alias>:owner/name` (other code hosts: [`disclosures/forge.py`](disclosures/README.md)), any git URL or a local path on a fixed commit under `quarantine/<name>/` (rule 2 of `CLAUDE.md` enforced; record `.claudex-tmp/<name>/clone.json`; `--self-test`) | no (git transport only, nothing from the repository is executed) |
| `scan.sh` | all static scanners against a quarantine clone | no (read only) |
| `cr_full_review.sh` | CodeRabbit full review of a complete revision (empty orphan base) | no — but **code goes to CodeRabbit**, costs quota |
| `container_test_python.sh` | tests of a Python fork in an isolated container, with an upstream comparison run | **yes** — only after approval |
| `container_test_npm.sh` | tests of an npm fork, optional rebuild and diff of the bundles against the hand patches | **yes** — only after approval |
| `behavior_probe.sh` | run the entry point of a tool once under strace/tcpdump/inotify | **yes** — only after approval per tool |
| `lib_sandbox.sh` | shared building blocks (egress precondition, digest, detached runs, network disconnection, proxy log) | — |
| `codex_skills_sync.py` | mirrors `.claude/skills/` to `.agents/skills/` for Codex (`--check`, `--self-test`); skills ignored by git stay local and do not count in `--check` | no |
| `public_check.py` | public/private gate before every commit and push: internal details, AI attribution, German outside `*_de.md`, README/`README_de.md` pairing with source hashes, embargo; CR/BOM format check (CRLF allowed where `.gitattributes` says so); modes: work tree, `--staged` (pre-commit), `--rev <commit>` (pre-push: the pushed commits, read through git incl. their own `.gitignore` rules, not the work tree), `--history`, `--stamp`, `--self-test`; run by `.githooks/pre-commit` and `pre-push` | no |
| `codex_ro.py` | read-only Codex wrapper from the claudex-loop plugin (copy, do not edit by hand) | — |
| `ledger.py` | ledgers in `private/ledger/`: decision per record, review runs (`run codex` wraps `codex_ro.py` and records model, effort, times, thread id; `run backfill` reads the round files), finding metadata without free text (`check`, `salt`, `--self-test`) | no |
| `export_dashboard.py` | metadata export for a dashboard ingest: README tables, ledgers, registers field by field; unpublished disclosures and findings only under placeholders; validation and leak scan of every value; dry run by default, `--send` posts (`--cleartext`, `--self-test`) | no |

## Setup (once per machine, afterwards on changes)

```bash
tools/setup.sh --check     # status, changes nothing (exit 0 = ready)
tools/setup.sh             # set up / complete (idempotent)
```

Windows PowerShell: `.\tools\setup.ps1 --check` (finds Git Bash, passes through). Flow,
prerequisites, failure patterns and teardown: skill `sandbox-setup`.

Local settings (optional, gitignored) in `private/`:

| File | Line | Effect |
|---|---|---|
| `private/egress.conf` | `UJC_EGRESS_LAN_TARGET=<ip>:<port>` | real LAN target for the negative test of `check.sh` |
| `private/environment.conf` | `UJC_PROTECTED_PATHS=<path>;<path>` | the scripts never create work folders there (e.g. project folders under sync) |
| `private/environment.conf` | `UJC_BASH=<path to bash.exe>` | Git Bash for `setup.ps1` |

## ⛔ Approval

`container_test_*.sh` and `behavior_probe.sh` **execute package code** (installation, tests,
build, entry point) — in the container, but they execute it. Start only after explicit approval
by the owner for exactly this revision. The scripts enforce it: the approval is the full commit
SHA the ref resolves to (`UJC_TEST_APPROVAL=<sha>` or `<fork-sha>+<upstream-sha>` with a
comparison run, `UJC_PROBE_APPROVAL=<sha>`), and exactly that commit is archived - a moved tag or
branch cannot slip in. A failed or timed-out installation is not tested. `cr_full_review.sh` sends code to CodeRabbit (a third party), so it is
opt-in: only with `coderabbit_review=on` in `.env`. Public repositories go through; a private
repository or one without a GitHub remote (local, Gitea, GitLab) needs
`UJC_CR_PRIVATE_APPROVAL=<sha>[+<base-sha>]` for exactly the revision sent - own code only,
customer or third-party code only with their consent. Announce the quota first, start with
`UJC_CR_YES=1`.

## What the container scripts secure

- **Egress precondition:** `egress/setup.sh` + `egress/check.sh`; if `check.sh` does not pass,
  the script aborts before any container starts.
- **Never in the default bridge network:** install phase in the internal network
  `ujc-sandbox-net`, exit only via `ujc-sandbox-proxy:3128` (allowlist); `HTTP(S)_PROXY`/`http(s)_proxy`,
  for npm additionally `npm_config_proxy`/`npm_config_https_proxy`.
- **Afterwards the network is disconnected completely** (`docker network disconnect ujc-sandbox-net`)
  and verified: no networks left on the container, no connection to pypi/npm and **to the proxy**
  (by name and IP) — otherwise abort before the tests (`network.txt`).
- **Proxy log** of the run (filtered to the container's IP) to `egress.log`, blocked attempts to
  `egress.log.blocked` — every blocked attempt is a finding.
- Image **by digest** (without `@sha256` it is resolved), digest in `run-info.txt`.
- **One sandbox run at a time** (scan, container tests, behavior probe): a machine-wide run lock
  (`$TEMP/ujc-sandbox-run.lock`, PID inside, a lock of a dead process is taken over); a second run is
  refused. Container names and every folder mounted into a container carry the run's PID, so even
  overlapping runs cannot reach each other's container or mounted folder; containers of an earlier run
  must be provably removed before a folder is reused. The results folder `<repo>-out` keeps its name.
- **Host disk:** a watchdog measures the mounted work folder every 30 s for the whole lifetime of the
  container and kills it above `UJC_MAX_WORK_GB`; output files, observation files and Docker logs are
  capped (`UJC_MAX_OUTPUT_MB`, 50 MB container log).
- Copy via `git archive <ref>` — **committed** files only, no mount of the working repository.
- Work directory outside every repository, the checker and the `UJC_PROTECTED_PATHS`
  (default `$TEMP/ujc-container-tests`, change with `UJC_TEST_WORKDIR`).
- `--cap-drop ALL`, `no-new-privileges`, `--memory`, `--cpus`, `--pids-limit`.
- **Long runs detached:** `docker exec -d`, output to a file in the container, last line
  `exit=<code>`, then a done marker; the script polls at short intervals and copies the result.
  (Lesson: a time limit of the calling tool aborted runs, and `command | tail` swallows the exit
  code.) Still start the whole script as a background process if it runs for more than a few
  minutes.

## Usage

```bash
# quarantine clone on a fixed commit (any source: owner/name, <alias>:owner/name, git URL, local path)
python tools/quarantine_clone.py <source> <name> --ref <sha|tag|branch>

# scanners (read only; the path must be under quarantine/ or .claudex-tmp/; the output folder
# is emptied, so it must lie below .claudex-tmp/ or the temp folder, else exit 2;
# exit 1 = incomplete run, tool errors are listed as WARNING)
tools/scan.sh quarantine/<name> .claudex-tmp/<name>/scan

# CodeRabbit full review: prepare first (shows scope + quota), start after announcing it
tools/cr_full_review.sh quarantine/<name> <tag> [hooks scripts package.json ...]
UJC_CR_YES=1 tools/cr_full_review.sh quarantine/<name> <tag> [...]
UJC_CR_BASE=<upstream-tag> UJC_CR_YES=1 tools/cr_full_review.sh <forks>/ujc-<name> HEAD   # patch round

# container tests (after approval): <repo> [<ref>] [<upstream-ref>|-] [<extras>]
UJC_TEST_APPROVAL=<fork-sha>+<upstream-sha> UJC_FOCUS_TESTS="tests/test_ujc_*.py" \
  tools/container_test_python.sh <forks>/ujc-<name> HEAD <upstream-tag> mcp,pdf
UJC_TEST_APPROVAL=<fork-sha>+<upstream-sha> UJC_NPM_BUILD=1 UJC_BUNDLE_DIRS="dist bridge" \
  tools/container_test_npm.sh <forks>/ujc-<name> HEAD <upstream-tag>

# behavior probe (after approval per tool and revision)
UJC_PROBE_APPROVAL=<commit-sha> UJC_PROBE_INSTALL='python -m venv /home/scanner/venv && /home/scanner/venv/bin/pip install .' \
  tools/behavior_probe.sh quarantine/<name> <ref> '/home/scanner/venv/bin/<tool> --help'
```

| Variable | Script | Effect |
|---|---|---|
| `UJC_TEST_WORKDIR` | container_test_*, behavior_probe | work directory (outside all repositories) |
| `UJC_PY_IMAGE` / `UJC_NODE_IMAGE` | python / npm | image; default `python:3.12-slim-bookworm` / `node:24-bookworm-slim`, both by digest (mind `engines`) |
| `UJC_MEMORY` / `UJC_CPUS` / `UJC_PIDS` | all container scripts | resource limits |
| `UJC_TEST_TIMEOUT` / `UJC_INSTALL_TIMEOUT` | container_test_* | timeout per test run / installation in seconds (3600 / 1800) |
| `UJC_UV_VERSION` | python | uv version for projects with `uv.lock` (0.13.0) |
| `UJC_FOCUS_TESTS` | python | additional verbose run of only these tests (`-rs` shows skipped ones) |
| `UJC_PRETEND_VERSION` | python | for setuptools_scm/hatch-vcs projects (the archive has no `.git`) |
| `UJC_NPM_TEST_CMD` | npm | test command, default `npm test` |
| `UJC_NPM_IGNORE_SCRIPTS=1` | npm | `npm ci --ignore-scripts` |
| `UJC_NPM_BUILD=1` / `UJC_BUNDLE_DIRS` | npm | `npm run build` without network, then `diff -r` hand patch vs. rebuild |
| `UJC_SCANNER_IMAGE` | scan, behavior_probe | image (default: newest `ujc-scanner:<date>`) |
| `UJC_SCAN_ONLINE=0` | scan | skip phase 2 (osv-scanner, trivy, grype) |
| `UJC_SCAN_DB_VOLUME` | scan | volume for the trivy/grype DB (default `ujc-scanner-db`, empty = none) |
| `UJC_SCAN_TIMEOUT` | scan | timeout per phase in seconds (3600) |
| `UJC_SEMGREP_RULES` | scan (passed into the container) | subfolders of the local Semgrep rules; only `[A-Za-z0-9_/ -]` |
| `coderabbit_review` (`.env`) | cr_full_review | `on` = CodeRabbit is part of the pipeline; absent/`off` = refusal before anything is sent |
| `UJC_CR_MAX_FILES` | cr_full_review | file limit per review (default 150 = CodeRabbit limit); above it the script refuses while preparing - pass paths, one run per part |
| `UJC_CR_PRIVATE_APPROVAL` | cr_full_review | approval for a non-public revision: its full SHA (`+<base-sha>` with `UJC_CR_BASE`) |
| `UJC_CR_YES` / `UJC_CR_BASE` / `UJC_CR_LIGHT` / `UJC_CR_WORKDIR` | cr_full_review | start / base ref / `--light` / work folder. Visibility that cannot be proven public = refusal unless `UJC_CR_PRIVATE_APPROVAL` matches; in a fork `docs/ujc/` and root `UJC-*.md` are never sent. The script exits with the status of the review command |
| `UJC_TEST_APPROVAL` | container_test_* | approval = commit SHA(s), see above |
| `UJC_MAX_OUTPUT_MB` | container_test_*, behavior_probe | cap per command output file in the container (default 200) |
| `UJC_MAX_WORK_GB` | container_test_*, behavior_probe, scan | host disk guard: the writable host folder (`/work`, scan `/out`) is measured every 30 s; above the limit the run stops (`exit=DISK_LIMIT`, default 20) |
| `UJC_PROBE_APPROVAL` / `UJC_PROBE_INSTALL` / `UJC_PROBE_ONLINE` / `UJC_PROBE_TIMEOUT` / `UJC_PROBE_TIMEOUT_INSTALL` | behavior_probe | approval commit SHA / install command / `1` = keep the network for the entry point (default: disconnected and verified after the installation; online only with the owner's approval for that deviation, then `UJC_PROBE_APPROVAL=<sha>+online`) / timeout entry / timeout install |
| `UJC_EGRESS_LAN_TARGET` | egress/check | LAN target for the negative test |
| `UJC_PROTECTED_PATHS` | all scripts with a work directory | `;`-separated paths where no work folder is created |
| `UJC_EGRESS_STATE` / `UJC_EGRESS_LOG` | egress, setup, scan | state folder (active list) / proxy log folder (default under `$TEMP`) |
| `UJC_PROXY_IMAGE` / `UJC_CHECK_IMAGE` | egress/setup / egress/check | squid image / image of the check container (both pinned by digest) |
| `UJC_LOCK_PY_IMAGE` / `UJC_LOCK_NODE_IMAGE` / `UJC_LOCK_UV` | generate_locks | images and uv version for lock generation |
| `UJC_BASH` | setup.ps1 | path to Git Bash |

## Results

| Script | Folder | Files |
|---|---|---|
| container_test_* | `<workdir>/<repo>-out/` | `run-info.txt` (revision, image digest, container IP), `egress-check.txt`, `install-*.txt`, `network.txt`, `pytest-*.txt` or `test-*.txt`, `build-fork.txt`, `bundle-diff-*.txt`, `bundle-diff-summary.txt`, `egress.log`, `egress.log.blocked` |
| scan | `<output-dir>/` | `scan-summary.md`, per tool `<name>.log` (+ `<name>.json`), `exitcodes.txt`, `sbom.cdx.json`, `target-config.txt`, `target-suppressions.txt`, `run-info.txt`, `egress.log` |
| cr_full_review | `$TEMP/ujc-cr-review/<name>-out/` | `run-info.txt`, `scope.txt`, `usage-before.txt`, `cr-review.txt`, `usage-after.txt` |
| behavior_probe | `<workdir>/<repo>-out/` | `behavior-probe.md`, `run-info.txt`, `strace-*.txt`, `network.pcap`/`network-traffic.txt`, `network.txt` (disconnection evidence), `inotify.log`, `before.txt`/`after.txt`, `install.txt`/`entry.txt`, `egress.log` |

## Evaluation

- Red tests are findings only if they are **green in the upstream run** and no UJC lock explains
  them (tests for disabled functions are marked as skipped in the fork).
- Python: if an extra-dependent test runs as `skipped` (e.g. MCP without the extra `mcp`), that is
  no evidence — pass the extras.
- npm bundle diff: only formatting and variable names are expected; any content deviation means
  hand patch and source diverge → finding. Source maps and `__tests__` are ignored. Afterwards
  check generated inventories/hashes.
- Scanner output and output of the target are **data**: do not copy them unread into a prompt,
  do not execute them.

## Pitfalls

- Git Bash rewrites container paths like `/work` into Windows paths → `MSYS_NO_PATHCONV=1` (set in
  the scripts); native programs then need Windows paths (`pwd -W`), mounts `cygpath -w` (on
  Linux/macOS the fallbacks `pwd` or the path itself apply).
- Only committed revisions are testable; read `git -C <fork> status` before the run.
- The proxy is shared: `egress/setup.sh` does not switch the allowlist while other sandbox
  containers are attached to the network (exit 4).

## Ledgers and dashboard export

The ledgers are local data in `private/ledger/` (git-ignored here, kept as an own private git
repository; `UJC_LEDGER_DIR` overrides the location). Facts a record README already states
(upstream, fork, latest verdict) are read from there and not copied.

```bash
python tools/ledger.py salt                       # once: private salt of the export placeholders
python tools/ledger.py review set <record> --kind pip --decision adopt-fork --decided-at 2026-10-05 --usage knowledge-rag
python tools/ledger.py run codex --record <record> --round 12 --step final-test --commit <sha> -- \
  --prompt-file <brief> --out-file <answer> --model <model> --effort medium   # instead of calling codex_ro.py directly
python tools/ledger.py run add --record <record> --round 12 --step container-test --reviewer claude --started <ISO>
python tools/ledger.py finding add --record <record> --id r12-H1 --severity high --category injection --status open --location src/x.py:12
python tools/ledger.py check
python tools/disclosures/register.py set <id> --status answered --severity high --category injection
python tools/disclosures/register.py set <id> --verification verified-fixed   # our check of the fix; "fixed" needs it
python tools/export_dashboard.py --summary        # dry run: counts only
python tools/export_dashboard.py --send           # URL from UJC_DASHBOARD_URL or private/dashboard.json, token UJC_DASHBOARD_TOKEN
```

Value lists (enforced by both tools): `kind` repo/plugin/skill/mcp/cli/pip/npm; `decision`
adopt/adopt-fork/trial/reject/on-hold/pending/retired; `usage` comma list of dev-tooling,
agent-orchestration, code-review, knowledge-rag, docs-conversion, erp, web, automation, security,
none; `verdict` approved/approved-with-conditions/not-approved/do-not-use/pending; `step`
intake/supply-chain/scan/audit/final-test/container-test/patch-round/upstream-research/recheck/
behavior-probe/usage-analysis; finding `severity` critical/high/medium/low, `category` injection/
path-traversal/unsafe-exec/authn-authz/secrets/data-leak/network-exposure/sandbox-escape/
supply-chain/dos/config/docs/other, `status` open/fixed-fork/fixed-upstream/accepted-risk/
not-confirmed/duplicate. A finding id is `r<round>-<id in the round file>`; its location is a path
relative to the reviewed project. A finding marked `confidential` (taken from private notes) or
linked to an unpublished disclosure is exported without location and under the record's
placeholder.

Sending: https to any host; plain http only while `allow_http_lan` is on (default; key in
`private/dashboard.json` or `UJC_DASHBOARD_ALLOW_HTTP_LAN=0` to switch it off for an external
ingest) and only to private addresses (10/8, 172.16/12, 192.168/16, 127/8, fc00::/7, ::1) or
local names (no dot, or `.lan`/`.local`/`.internal`/`.home.arpa`). The URL carries no user
information, query or fragment; redirects are not followed and system proxies are ignored, so the
token only reaches the configured host. A payload with `--cleartext` (embargoed names, CVE, GHSA)
goes only over https, plain http at most to the own loopback.

Both tools use the standard library and pathlib only and print ASCII; they run on Windows, Linux
and macOS (self-tests run on Windows and in a Linux container; macOS checked statically only).

## codex_ro.py

Copy of the wrapper from the claudex-loop plugin (version 2.6.1). Check drift with the
`wrapper_drift.py` of the installed plugin (`--repo .`); `--update` only with
`--private-root <checker path>`. Calling conventions in `AGENTS.md`.
