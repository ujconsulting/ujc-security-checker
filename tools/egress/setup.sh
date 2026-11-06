#!/usr/bin/env bash
# Sets up the egress environment for sandbox containers (idempotent):
#   - internal Docker network ujc-sandbox-net (--internal: no direct exit, no LAN)
#   - proxy container ujc-sandbox-proxy (Squid) with one leg in the internal network and one in the
#     default bridge network; it only passes domains of the active allowlist and hard-blocks
#     private networks (squid.conf)
# Sandbox containers: --network ujc-sandbox-net, HTTP(S)_PROXY=http://ujc-sandbox-proxy:3128
# Log: ${UJC_EGRESS_LOG:-$TEMP/ujc-egress-log}/access.log
#
# Usage:  setup.sh [--rebuild] [<list> ...]
#   <list>     standard (allowlist.txt, package sources - default) | scanner (allowlist-scanner.txt,
#              vulnerability databases) | any name <n> with a file allowlist-<n>.txt
#              Several names = union. The active list is switched WITHOUT restarting the proxy
#              (squid -k reconfigure); it applies to ALL sandbox containers at the same time.
#   --rebuild  recreate the proxy container (only needed after changes to squid.conf or mounts)
# Active list: ${UJC_EGRESS_STATE:-$TEMP/ujc-egress-state}/allowlist.txt, its name in list.txt
set -u
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
NET=ujc-sandbox-net
PROXY=ujc-sandbox-proxy
# Squid image by digest (as of 2026-10-10, Ubuntu 24.04); change deliberately, then setup.sh --rebuild
IMAGE="${UJC_PROXY_IMAGE:-ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029}"
LOG="${UJC_EGRESS_LOG:-${TEMP:-/tmp}/ujc-egress-log}"
LOG="$(mkdir -p "$LOG" && cd "$LOG" && { pwd -W 2>/dev/null || pwd; })"
STATE="${UJC_EGRESS_STATE:-${TEMP:-/tmp}/ujc-egress-state}"
STATE="$(mkdir -p "$STATE" && cd "$STATE" && { pwd -W 2>/dev/null || pwd; })"

REBUILD=0
LISTS=""
for a in "$@"; do
  case "$a" in
    --rebuild) REBUILD=1 ;;
    -*) echo "ERROR: unknown option $a" >&2; exit 2 ;;
    *) LISTS="$LISTS $a" ;;
  esac
done
[ -n "$LISTS" ] || LISTS=" standard"
LISTS="${LISTS# }"

# The list applies to all sandbox containers: do not switch the list or recreate the proxy while
# others are attached to the network
PREV="$(cat "$STATE/list.txt" 2>/dev/null || true)"
if { [ "$REBUILD" = "1" ] || { [ -n "$PREV" ] && [ "$PREV" != "$LISTS" ]; }; } && docker network inspect "$NET" >/dev/null 2>&1; then
  OTHERS="$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$NET" | tr ' ' '\n' | grep -v -x -e "$PROXY" -e '' || true)"
  if [ -n "$OTHERS" ]; then
    echo "ERROR: list \"$PREV\" is active and these containers are attached to network $NET: $(echo "$OTHERS" | tr '\n' ' ') - wait for their runs to finish" >&2
    exit 4
  fi
fi

# assemble the active list (comments and blank lines removed)
TMPL="$STATE/allowlist.new"
: > "$TMPL"
for n in $LISTS; do
  case "$n" in
    standard) f="$HERE/allowlist.txt" ;;
    *[!a-z0-9-]*) echo "ERROR: invalid list name $n" >&2; exit 2 ;;
    *) f="$HERE/allowlist-$n.txt" ;;
  esac
  [ -f "$f" ] || { echo "ERROR: list missing: $f" >&2; exit 2; }
  sed -e 's/#.*//' -e 's/[[:space:]]//g' -e '/^$/d' "$f" >> "$TMPL"
done
sort -u "$TMPL" > "$STATE/allowlist.txt"
rm -f "$TMPL"
echo "$LISTS" > "$STATE/list.txt"

# --internal alone still gives the HOST an address on the bridge (the gateway): every service of the
# Docker host / Docker Desktop VM bound to 0.0.0.0 is then reachable from the sandbox, past the proxy
# (measured 12.10.2026: rpcbind 111, rpc.statd). gateway_mode_ipv4=isolated (Docker Engine 28+)
# leaves the host without an address on the bridge - containers only reach each other (the proxy).
GWMODE_OPT="com.docker.network.bridge.gateway_mode_ipv4"
if docker network inspect "$NET" >/dev/null 2>&1 \
   && [ "$(docker network inspect -f "{{index .Options \"$GWMODE_OPT\"}}" "$NET")" != "isolated" ]; then
  OTHERS="$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$NET" | tr ' ' '\n' | grep -v -x -e "$PROXY" -e '' || true)"
  [ -z "$OTHERS" ] || { echo "ERROR: $NET must be recreated (isolated gateway), but containers are attached: $(echo "$OTHERS" | tr '\n' ' ')" >&2; exit 4; }
  echo "recreating $NET with an isolated gateway (the host must not have an address on the sandbox bridge)"
  docker rm -f "$PROXY" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null || { echo "ERROR: cannot remove $NET" >&2; exit 2; }
fi
docker network inspect "$NET" >/dev/null 2>&1 \
  || docker network create --internal -o "$GWMODE_OPT=isolated" --label ujc.sandbox=1 "$NET" >/dev/null \
  || { echo "ERROR: cannot create $NET with $GWMODE_OPT=isolated (Docker Engine 28+ required)" >&2; exit 2; }
[ "$(docker network inspect -f '{{.Internal}}' "$NET")" = "true" ] || { echo "ERROR: $NET is not --internal" >&2; exit 2; }
[ "$(docker network inspect -f "{{index .Options \"$GWMODE_OPT\"}}" "$NET")" = "isolated" ] || { echo "ERROR: $NET gateway is not isolated" >&2; exit 2; }
# Proxy clients = subnet(s) of the internal network only (squid.conf: acl sandbox_clients)
docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' "$NET" | sed '/^$/d' > "$STATE/clients.txt"
[ -s "$STATE/clients.txt" ] || { echo "ERROR: no subnet found for $NET" >&2; exit 2; }

# A proxy from an older version (allowlist mounted as a single file) is recreated once
if docker ps -a --format '{{.Names}}' | grep -qx "$PROXY"; then
  docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "$PROXY" | grep -q '/etc/squid/ujc' || REBUILD=1
fi

if [ "$REBUILD" = "1" ]; then docker rm -f "$PROXY" >/dev/null 2>&1; fi
if ! docker ps --format '{{.Names}}' | grep -qx "$PROXY"; then
  docker rm -f "$PROXY" >/dev/null 2>&1
  docker run -d --name "$PROXY" --label ujc.sandbox=1 \
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE \
    --security-opt no-new-privileges --memory 256m --pids-limit 200 \
    -v "$HERE/squid.conf:/etc/squid/squid.conf:ro" \
    -v "$STATE:/etc/squid/ujc:ro" \
    -v "$LOG:/var/log/squid" \
    "$IMAGE" >/dev/null || { echo "ERROR: proxy start" >&2; exit 1; }
  docker network connect --alias "$PROXY" "$NET" "$PROXY"
  # wait until Squid is listening (otherwise the first check fails)
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    docker exec "$PROXY" sh -c 'test -s /run/squid.pid' 2>/dev/null && break
    sleep 1
  done
else
  # running proxy: load the new list; as user proxy, because the container runs without CAP_KILL
  docker exec -u proxy "$PROXY" squid -k reconfigure -f /etc/squid/squid.conf > "$STATE/reconfigure.txt" 2>&1 \
    || { echo "ERROR: squid -k reconfigure (see $STATE/reconfigure.txt)" >&2; exit 1; }
  sleep 2
fi
echo "network=$NET proxy=$PROXY image=$(docker inspect -f '{{.Image}}' "$PROXY") list=\"$LISTS\" log=$LOG/access.log"
