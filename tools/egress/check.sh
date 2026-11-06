#!/usr/bin/env bash
# Checks the egress environment in both directions. Exit 0 only if ALL checks pass.
#   allowed:  the targets of the active list via the proxy (standard: pypi/npm, scanner: OSV API)
#   blocked:  direct exit without proxy, LAN targets (also via the proxy), host,
#             domains that are not allowlisted
# LAN target (<ip>:<port> of a real service in your own network), in this order:
#   1. parameter, 2. environment UJC_EGRESS_LAN_TARGET, 3. private/egress.conf (gitignored),
#   4. otherwise generic: gateway of the Docker bridge network (= Docker host), port 80 - with a note.
# Active list: list.txt in the state folder of setup.sh
set -u
export MSYS_NO_PATHCONV=1
# shellcheck source=../lib_sandbox.sh
. "$(dirname "$0")/../lib_sandbox.sh"
NET=ujc-sandbox-net
PROXY=http://ujc-sandbox-proxy:3128
LAN="${1:-${UJC_EGRESS_LAN_TARGET:-}}"
if [ -z "$LAN" ]; then
  GW="$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null)"
  LAN="${GW:-172.17.0.1}:80"
  echo "NOTE: no LAN target configured (UJC_EGRESS_LAN_TARGET / private/egress.conf) - checking generic $LAN (gateway of the Docker bridge network)"
fi
IMG="${UJC_CHECK_IMAGE:-python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258}"
STATE="${UJC_EGRESS_STATE:-${TEMP:-/tmp}/ujc-egress-state}"
LIST="$(cat "$STATE/list.txt" 2>/dev/null || echo standard)"
docker ps --format '{{.Names}}' | grep -qx ujc-sandbox-proxy || { echo "ERROR: proxy ujc-sandbox-proxy not running - run setup.sh first"; exit 1; }
echo "active list: $LIST"
# -i is mandatory: without -i the check script never reaches the container and the run silently exits 0
# The host must have no address on the sandbox bridge (gateway_mode_ipv4=isolated, egress/setup.sh):
# otherwise every service of the Docker host / Docker Desktop VM bound to 0.0.0.0 is reachable from
# the sandbox, past the proxy (measured: rpcbind, rpc.statd). Checked as configuration AND by a full
# TCP sweep of the subnet's first address (the classic gateway) unless the proxy sits there.
GWMODE="$(docker network inspect "$NET" -f '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' 2>/dev/null)"
SUBNET="$(docker network inspect "$NET" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
# (the first usable address is computed inside the check container - no Python needed on the host)
# the proxy is the only peer on the network; besides 3128 nothing may answer there either
PXIP="$(docker inspect -f "{{with index .NetworkSettings.Networks \"$NET\"}}{{.IPAddress}}{{end}}" ujc-sandbox-proxy 2>/dev/null)"
docker run -i --rm --network "$NET" --cap-drop ALL --security-opt no-new-privileges \
  -e LAN="$LAN" -e PX="$PROXY" -e LIST="$LIST" -e SUBNET="$SUBNET" -e PXIP="$PXIP" -e GWMODE="$GWMODE" "$IMG" python - <<'EOF'
import os, socket, urllib.request, urllib.error
px = os.environ["PX"]; lan = os.environ["LAN"]; lists = os.environ["LIST"].split()
ok = True
def via_proxy(url):
    """Returns (status, blocked_by_proxy). blocked_by_proxy is True only if the answer provably
    comes from Squid itself (X-Squid-Error header, or a refused CONNECT tunnel) - a status code
    alone (403, 404, 500 ...) may come from a target the request did reach."""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": px, "https": px}))
    try:
        return op.open(url, timeout=15).status, False
    except urllib.error.HTTPError as e:
        squid = e.headers.get("X-Squid-Error")
        # the target answered with an error status (int) - unless Squid generated the page itself
        return (f"{e.code} {squid}" if squid else e.code), bool(squid)
    except Exception as e:
        msg = str(e)
        return f"{type(e).__name__} {msg[:60]}", "Tunnel connection failed" in msg
def direct(host, port):
    try:
        socket.create_connection((host, port), 5).close(); return "CONNECTED"
    except Exception as e:
        return type(e).__name__
def check(name, got, want_ok):
    global ok
    # allowed = the proxy built the tunnel and the target answered with an HTTP status that is
    # not a proxy denial; blocked = Squid answered itself, or (direct) no connection at all
    if want_ok:
        status, by_proxy = got
        good = isinstance(status, int) and not by_proxy
        shown = status
    elif isinstance(got, tuple):
        status, by_proxy = got
        good = by_proxy
        shown = status
    else:
        good = got != "CONNECTED"
        shown = got
    ok = ok and good
    print(("OK    " if good else "FAILED") + f" {name}: {shown}")
if "standard" in lists:
    check("package source via proxy (pypi.org)", via_proxy("https://pypi.org/simple/pip/"), True)
    check("package source via proxy (npm)", via_proxy("https://registry.npmjs.org/left-pad"), True)
else:
    check("package source blocked, list without standard (pypi.org)", via_proxy("https://pypi.org/simple/pip/"), False)
if "scanner" in lists:
    check("vulnerability DB via proxy (api.osv.dev)", via_proxy("https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000"), True)
check("direct exit without proxy (pypi.org:443)", direct("pypi.org", 443), False)
h, p = lan.split(":")
check(f"LAN direct ({lan})", direct(h, int(p)), False)
check(f"LAN via proxy (http://{lan}/)", via_proxy(f"http://{lan}/"), False)
check("host via proxy (host.docker.internal)", via_proxy("http://host.docker.internal/"), False)
check("non-allowlisted domain via proxy (example.com)", via_proxy("https://example.com/"), False)
check("plain HTTP to a non-standard port via proxy (pypi.org:8080)", via_proxy("http://pypi.org:8080/"), False)
def sweep(host, allowed=()):
    """All 65535 TCP ports of host directly (no proxy); returns the ports that accept a connection
    and are not in allowed. Refused ports answer at once, filtered ones cost the short timeout."""
    import concurrent.futures
    def probe(port):
        try:
            socket.create_connection((host, port), 0.5).close()
            return port
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as pool:
        open_ports = [p for p in pool.map(probe, range(1, 65536)) if p]
    return [p for p in open_ports if p not in allowed]
import ipaddress
try:
    gw = str(next(ipaddress.ip_network(os.environ.get("SUBNET", "")).hosts()))
except (ValueError, StopIteration):
    gw = ""
pxip = os.environ.get("PXIP", "")
gwmode = os.environ.get("GWMODE", "")
good = gwmode == "isolated"
ok = ok and good
print(("OK    " if good else "FAILED") + f" host without address on the sandbox bridge (gateway_mode_ipv4={gwmode or 'unset'})")
if gw and gw != pxip:
    extra = sweep(gw)
    check(f"first subnet address direct ({gw}, all 65535 TCP ports)", "CONNECTED" if extra else "none open", False)
    if extra:
        print(f"       open: {extra}")
elif not gw:
    print("FAILED subnet of the internal network unknown - cannot check it")
    ok = False
if pxip:
    extra = sweep(pxip, allowed=(3128,))
    if extra:
        check(f"proxy {pxip}: only 3128 (all 65535 TCP ports)", "CONNECTED", False)
        print(f"       open besides 3128: {extra}")
    else:
        check(f"proxy {pxip}: only 3128 (all 65535 TCP ports)", "none open besides 3128", False)
print("RESULT: " + ("all checks passed" if ok else "AT LEAST ONE CHECK FAILED"))
raise SystemExit(0 if ok else 1)
EOF
