<!-- source: SKILL.md sha256:4b2c025b9e66a1a4750f769432981309b9163c4b87f56ad058986751156aff42 -->
[English](README.md) | [Deutsch](README_de.md)

# sandbox-setup

Short human documentation. The agents load [`SKILL.md`](SKILL.md), which is authoritative.

## Purpose

Sets up, checks, renews and tears down the sandbox on a machine with Docker through one idempotent
entry point, `tools/setup.sh` (Windows: `tools/setup.ps1`): the internal network
`ujc-sandbox-net`, the Squid egress proxy `ujc-sandbox-proxy` with its allowlist, the egress check
and the scanner image `ujc-scanner:<date>`. Apart from ShellCheck (required, lints this repository's
own scripts) nothing is installed on the host; all scanners live in the image.

## When to use

- first setup on a machine;
- before a scanner run, container test or behavior probe (status check);
- `setup.sh` or `check.sh` reports an error;
- scanner versions or lock files changed (rebuild);
- the sandbox is to be removed.

## Flow

Six steps in a fixed order, stopping at the first error: (1) prerequisites (Docker with Linux
containers on amd64, bash 4.4+, git, ShellCheck), (2) egress network and proxy, (3) `tools/egress/check.sh` -
checks in both directions, not green = abort, (4) scanner image (built only if the repository state
changed), (5) every tool in the image starts once without network, (6) shell scripts and git hooks pass
`bash -n` and `shellcheck -S warning`, base images present by digest.

## Commands

```bash
tools/setup.sh --check     # status only, changes nothing; exit 0 = ready
tools/setup.sh             # set up or complete
tools/setup.sh --rebuild   # recreate the proxy, rebuild the image without cache
tools/setup.sh --remove    # teardown (only objects by name; logs and base images stay)
```

```powershell
.\tools\setup.ps1 --check  # Windows: finds Git Bash (or UJC_BASH), passes through
```

Optional local settings in `private/egress.conf` (`UJC_EGRESS_LAN_TARGET`) and
`private/environment.conf` (`UJC_PROTECTED_PATHS`, `UJC_BASH`).

## Example

After a Docker Desktop restart `tools/setup.sh --check` reports "proxy ujc-sandbox-proxy not
running"; `tools/setup.sh` starts it again, step 3 passes, the last line reads
`RESULT: sandbox ready (image ujc-scanner:<date>)`.

## See also

[`docs/SETUP.md`](../../../docs/SETUP.md), [`tools/egress/README.md`](../../../tools/egress/README.md),
[`tools/scanner-image/README.md`](../../../tools/scanner-image/README.md),
[`docker-sandbox`](../docker-sandbox/README.md).
