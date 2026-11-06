<!-- source: SKILL.md sha256:44c8ecbc9f511f6e4b3085b307d59b979c5f620616a2b45727b06f062dd5afc3 -->
[English](README.md) | [Deutsch](README_de.md)

# docker-sandbox

Short human documentation. The agents load [`SKILL.md`](SKILL.md), which is authoritative.

## Purpose

Rules and the standard pattern for throwaway Docker containers that install, test or run
third-party code: container tests, bundle rebuilds, CLI or MCP trial runs and the behavior probe.
A container run executes package code, so it happens **only after explicit approval** for exactly
this tool and revision.

## When to use

- step 11 (container tests) or 11b (behavior probe) of `tool-review` is due;
- a third-party package or MCP server is to be tried out;
- a container test script is written or changed;
- it has to be decided whether Docker is enough or an LXC or Windows VM is needed.

## Flow

1. Approval present; fork or clone state committed.
2. `tools/setup.sh --check` -> exit 0.
3. Start the script (long runs in the background); it checks egress, records the image digest and
   runs detached.
4. `network.txt` must contain `network_disconnected`, otherwise the run does not count.
5. Read `egress.log` / `egress.log.blocked` - every blocked attempt is a finding.
6. Evaluate against an upstream comparison run; record the result as a round in
   `private/records/<name>/reviews/` (upstream state) or `private/repos/<name>/reviews/` (own version).

The mandatory network rule: never the default bridge network or `--network host`; installation
only in `ujc-sandbox-net` via `ujc-sandbox-proxy:3128` after the egress check, then disconnect the
network completely and verify it. Further: source copied with `git archive` (no mount of the
working repository), work directory outside every repository, `--cap-drop ALL`,
`no-new-privileges`, resource limits, no Docker socket, no ports, no secrets, images by digest.

## Commands

```bash
UJC_FOCUS_TESTS="tests/test_ujc_*.py" tools/container_test_python.sh <fork> HEAD <upstream-tag> <extras>
UJC_NPM_BUILD=1 UJC_BUNDLE_DIRS="dist" tools/container_test_npm.sh <fork> HEAD <upstream-tag>
UJC_PROBE_APPROVAL=<commit-sha> tools/behavior_probe.sh quarantine/<name> <ref> '<entry point>'
docker ps -a --filter label=ujc.sandbox=1     # afterwards only the proxy may be listed
```

## Example

An npm fork with hand-patched bundles: after approval `UJC_NPM_BUILD=1 tools/container_test_npm.sh`
installs through the proxy, disconnects the network, runs the tests and rebuilds the bundles
without network; `bundle-diff-summary.txt` shows only formatting differences, so hand patches and
source agree.

## See also

[`tools/README.md`](../../../tools/README.md), [`tools/egress/README.md`](../../../tools/egress/README.md),
[`sandbox-setup`](../sandbox-setup/README.md), [`proxmox-lxc-sandbox`](../proxmox-lxc-sandbox/README.md).
