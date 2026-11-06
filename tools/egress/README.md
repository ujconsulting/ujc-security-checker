[English](README.md) | [Deutsch](README_de.md)

# egress — controlled exit for sandbox containers

## Purpose

A sandbox container needs network access to install packages — and exactly in that phase foreign
install scripts run (npm `preinstall`/`postinstall`, sdist builds). In Docker's default bridge
network they reach the whole LAN, the Docker host and other containers. Therefore (mandatory rule
in `CLAUDE.md`):

- Sandbox containers **never** run in the default bridge network.
- The install phase runs **only** in the internal network `ujc-sandbox-net`; the only exit is the
  proxy `ujc-sandbox-proxy:3128`, which passes allowlisted domains only.
- Afterwards the network is disconnected completely and the disconnection is verified.
- The proxy log of every run is copied into the results; **blocked attempts are a finding**
  (where did the tool want to go, and why?).

## Layout

```text
 sandbox container ──(ujc-sandbox-net, --internal: no route to the outside)──┐
                                                                             │ :3128
                                                     ujc-sandbox-proxy (Squid)
                                                     ├─ leg in ujc-sandbox-net
                                                     └─ leg in the bridge network ──> internet
```

| File | Content |
|---|---|
| `setup.sh` | creates network and proxy (idempotent), assembles the active list and loads it without a restart (`squid -k reconfigure`) |
| `check.sh` | checks both directions; exit 0 only if everything holds |
| `squid.conf` | rules: clients only from the subnet of `ujc-sandbox-net` (`clients.txt`, written by `setup.sh`); private/local networks are **always** blocked; only ports 80/443, only GET/HEAD/CONNECT; otherwise only the active list; every request is logged |
| `allowlist.txt` | list `standard`: package sources (PyPI, npm, GitHub downloads) |
| `allowlist-scanner.txt` | list `scanner`: vulnerability databases for `tools/scan.sh` (OSV API, trivy DB, grype DB) |

Squid image pinned by digest (`setup.sh`), container without unnecessary capabilities,
`no-new-privileges`, 256 MB, 200 processes.

## Usage

```bash
tools/egress/setup.sh                   # list standard (default)
tools/egress/setup.sh scanner           # list scanner
tools/egress/setup.sh standard scanner  # union
tools/egress/setup.sh --rebuild         # recreate the proxy (after changing squid.conf)
tools/egress/check.sh [<lan-ip>:<port>]
```

Normally neither is called directly: `tools/setup.sh` sets up and checks, and
`container_test_*.sh`, `scan.sh`, `behavior_probe.sh` call `setup.sh` + `check.sh` as a
precondition and abort if `check.sh` does not pass.

Sandbox containers get:

```bash
docker run --network ujc-sandbox-net \
  -e HTTP_PROXY=http://ujc-sandbox-proxy:3128 -e HTTPS_PROXY=http://ujc-sandbox-proxy:3128 \
  -e http_proxy=http://ujc-sandbox-proxy:3128 -e https_proxy=http://ujc-sandbox-proxy:3128 \
  -e NO_PROXY=localhost,127.0.0.1 ...
# npm additionally: -e npm_config_proxy=... -e npm_config_https_proxy=...
# afterwards:       docker network disconnect ujc-sandbox-net <container>  + disconnection probe
```

**What `check.sh` checks** (all must hold):

| Check | expected |
|---|---|
| package source via proxy (pypi, npm) — with list `standard` | reachable |
| OSV API via proxy — with list `scanner` | reachable |
| pypi via proxy when list `standard` is not active | blocked |
| direct exit without proxy | blocked (no DNS, no route) |
| LAN target directly and via the proxy | blocked |
| Docker host (`host.docker.internal`) via the proxy | blocked |
| non-allowlisted domain (`example.com`) | blocked |
| plain HTTP to a non-standard port (`pypi.org:8080`) | blocked |
| host has no address on `ujc-sandbox-net` (`gateway_mode_ipv4=isolated`); first subnet address swept (all TCP ports) unless the proxy sits there | required / nothing answers |
| proxy container directly, all 65535 TCP ports | only 3128 answers |

"Blocked via the proxy" counts only if the answer provably comes from Squid itself (header
`X-Squid-Error`, or a refused CONNECT tunnel). A plain status code such as 403 or 404 may come
from a target the request did reach and is a failure.

**LAN target:** parameter, otherwise `UJC_EGRESS_LAN_TARGET`, otherwise `private/egress.conf`
(gitignored, line `UJC_EGRESS_LAN_TARGET=<ip>:<port>` — a real service in your own network). If
none is set, `check.sh` generically checks the gateway of the Docker bridge network (= Docker host)
and says so.

**Log:** `${UJC_EGRESS_LOG:-$TEMP/ujc-egress-log}/access.log`, format
`<time> <client-ip> <result>/<status> <method> <target> <server-ip>`. The scripts copy the excerpt
of their run to `<output>/egress.log` (for container tests filtered to the container's IP) and the
blocked lines to `egress.log.blocked`.

**Extending the allowlist:** only deliberately, one domain per line (leading dot = including
subdomains), with the reason in the commit message. A blocked attempt in the log is a finding
first, and a candidate for the list only after review. For tools that need more network (arbitrary
downloads, own services, long-running operation): a sandbox LXC in a separated network (skill
`proxmox-lxc-sandbox`), do not widen the list.

**One list for everyone:** the proxy is shared. `setup.sh` does not switch the list while other
sandbox containers are attached to the internal network (exit 4) — wait for their runs first.

## Limits

- **Squid checks the target IP after DNS resolution.** The block on private networks therefore
  also applies when an allowed domain points to a private address (DNS rebinding) — the proxy never
  connects into the LAN.
- **HTTPS is a tunnel** (`CONNECT`): the proxy sees domain and port, not content, path or headers.
  An allowed domain (e.g. `github.com`, `raw.githubusercontent.com`) can also be used for
  exfiltration or for loading further code — the list limits the targets, not the data.
- No protection against what happens in the container **after** installation unless the network
  is disconnected — hence disconnection plus probe.
- Allowed package sources deliver arbitrary packages; the supply chain is checked by the lockfile,
  not by the proxy.
- DNS goes through the proxy (the container itself resolves nothing) — DNS tunnels out of the
  container are blocked as well.
- IPv6: `squid.conf` blocks private/local v6 ranges; the internal Docker network has no v6.
- **The host has no address on the sandbox bridge.** With `--internal` alone, the bridge gateway is
  the Docker host (on Docker Desktop: its VM, which also holds the Windows drive mounts), and every
  service bound to `0.0.0.0` there is reachable from the sandbox, past the proxy - measured on
  12.10.2026: rpcbind (111) and rpc.statd. `setup.sh` therefore creates the network with
  `com.docker.network.bridge.gateway_mode_ipv4=isolated` (Docker Engine 28+) and recreates an older
  network once; `check.sh` requires that mode and sweeps all TCP ports of the proxy (only 3128).
- `setup.sh --rebuild` refuses while other containers are attached to the network (exit 4).
