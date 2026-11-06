#!/usr/bin/env bash
# Behavior probe: run the entry point of a tool ONCE in a sandbox container and observe what it
# does - started programs, connection targets, written files.
#
# ONLY AFTER EXPLICIT APPROVAL BY THE OWNER PER TOOL AND REVISION - the probe executes foreign
# code. Without UJC_PROBE_APPROVAL=<commit-sha> (the full 40-character SHA the ref resolves to)
# the script aborts; exactly that commit is archived, so a moved tag or branch cannot slip in.
#
# Usage (Git Bash; start as a background process):
#   UJC_PROBE_APPROVAL=<commit-sha> tools/behavior_probe.sh <repo-path> <ref> '<entry>'
#     <repo-path>  quarantine clone or fork (committed revisions only, copied via git archive)
#     <entry>      command in the container, working directory /work/src, e.g.
#                  '/home/scanner/venv/bin/<tool> --help'  or  'node dist/cli.js --version'
#
# Environment (optional):
#   UJC_PROBE_INSTALL   install command before the entry point (also observed), e.g.
#                       'python -m venv /home/scanner/venv && /home/scanner/venv/bin/pip install .'
#   UJC_PROBE_ONLINE=1  keep the network (via the proxy) for the entry point. Default: the network
#                       is disconnected and verified after the installation (CLAUDE.md rule 10);
#                       online only with the owner's approval for exactly that deviation.
#   UJC_PROBE_TIMEOUT   timeout for the entry point in seconds (default 300)
#   UJC_PROBE_TIMEOUT_INSTALL  timeout for the installation in seconds (default 600)
#   UJC_SCANNER_IMAGE   image (default: newest ujc-scanner:<date>; has strace, tcpdump,
#                       inotify-tools, Python 3.12, Node 24)
#   UJC_TEST_WORKDIR    work directory OUTSIDE every repository (default $TEMP/ujc-behavior-probe)
#
# Observation (root in the container, results in /var/ujc-probe, unreadable for the target):
#   strace -f -e trace=execve,connect,openat  (target runs via `strace -u scanner` as uid 10001)
#   tcpdump -i any (pcap + text extract), inotifywait on home, /work, /tmp,
#   before/after file comparison of home and work directory, proxy log of the run.
# Network: internal network ujc-sandbox-net, exit only via the egress proxy (allowlist "standard").
# Result: <workdir>/<name>-out/behavior-probe.md plus raw data. Output is ASCII only.
set -u
export MSYS_NO_PATHCONV=1
# shellcheck source=lib_sandbox.sh
. "$(dirname "$0")/lib_sandbox.sh"

if [ $# -lt 3 ]; then
  echo "Usage: UJC_PROBE_APPROVAL=<commit-sha> $0 <repo-path> <ref> '<entry>'" >&2
  exit 2
fi
REPO="$(cd "$1" 2>/dev/null && { pwd -W 2>/dev/null || pwd; })" || { echo "ERROR: repository not found: $1" >&2; exit 2; }
REF="$2"
ENTRY="$3"
SHA="$(git -C "$REPO" rev-parse --verify "$REF^{commit}" 2>/dev/null)" || { echo "ERROR: unknown ref: $REF" >&2; exit 2; }
ONLINE="${UJC_PROBE_ONLINE:-0}"
# the online mode is a separate decision: its approval names it ("<sha>+online")
WANT="$SHA"; [ "$ONLINE" = "1" ] && WANT="$SHA+online"
if [ "${UJC_PROBE_APPROVAL:-}" != "$WANT" ]; then
  echo "ERROR: no approval. The behavior probe executes foreign code and only runs after" >&2
  echo "       explicit approval by the owner for exactly this commit (and mode):" >&2
  echo "       UJC_PROBE_APPROVAL=$WANT $0 ..." >&2
  exit 3
fi
INSTALL="${UJC_PROBE_INSTALL:-}"
ITMO="${UJC_PROBE_TIMEOUT_INSTALL:-600}"
RTMO="${UJC_PROBE_TIMEOUT:-300}"

IMAGE="${UJC_SCANNER_IMAGE:-}"
if [ -z "$IMAGE" ]; then
  TAG="$(docker image ls ujc-scanner --format '{{.Tag}}' | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' | sort -r | head -n 1)"
  [ -n "$TAG" ] || { echo "ERROR: no image ujc-scanner:<date> - run tools/setup.sh first" >&2; exit 1; }
  IMAGE="ujc-scanner:$TAG"
fi
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE")" || exit 1

CT="${UJC_TEST_WORKDIR:-${TEMP:-/tmp}/ujc-behavior-probe}"
CT="$(mkdir -p "$CT" && cd "$CT" && { pwd -W 2>/dev/null || pwd; })" || exit 2
ujc_check_workdir "$CT" "$REPO" || exit 2
# container name and mounted work folder are unique per run (PID): overlapping runs cannot reach
# each other's container or folder. The results folder OUT keeps its stable name.
NAME="ujc-probe-$(basename "$REPO" | tr -d '\n' | tr -c 'a-zA-Z0-9_.-' '-')-$$"
BASE="$CT/$(basename "$REPO")-$$"
OUT="$CT/$(basename "$REPO")-out"
# one sandbox run at a time (shared proxy, names and folders) - held until the script ends
ujc_run_lock "behavior_probe $REPO" || exit 1
trap 'ujc_run_unlock' EXIT
# a container of an earlier run must be provably gone before its mounted folder is reused
ujc_remove_proven "$NAME" || exit 1
rm -rf "${BASE:?}" "${OUT:?}"
mkdir -p "$BASE/src" "$OUT"
# host disk guard of ujc_run: this folder is mounted writable as /work (UJC_MAX_WORK_GB)
UJC_WATCH_DIR="$BASE"

ujc_egress_prepare standard || exit 1
git -C "$REPO" archive "$SHA" | tar -x -C "$BASE/src" || { echo "ERROR: git archive $SHA" >&2; exit 1; }
{
  echo "revision=$SHA repo=$REPO image=$IMAGE id=$IMAGE_ID"
  echo "approval=$UJC_PROBE_APPROVAL"
  echo "install=$INSTALL"
  echo "entry=$ENTRY"
  echo "online=$ONLINE begin=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/run-info.txt"

ujc_remove_proven "$NAME" || exit 1
trap 'ujc_disk_guard_stop; docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "${BASE:?}"; ujc_run_unlock' EXIT
ujc_log_start
# Root needs NET_RAW (tcpdump), SETUID/SETGID (strace -u) and SYS_PTRACE (strace attaches to the
# target after it switched to uid 10001 - without it: "PTRACE_SEIZE: Operation not permitted").
# The target runs as uid 10001 and loses all capabilities with the uid switch; no-new-privileges
# prevents setuid programs.
docker run -d --name "$NAME" --label ujc.sandbox=1 --log-driver json-file --log-opt max-size=50m --log-opt max-file=1 --user 0 \
  --network "$UJC_NET" "${UJC_PROXY_ENV[@]}" "${UJC_NPM_PROXY_ENV[@]}" \
  --cap-drop ALL --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges \
  --memory "${UJC_MEMORY:-4g}" --cpus "${UJC_CPUS:-2}" --pids-limit "${UJC_PIDS:-512}" \
  -v "$(ujc_host_path "$BASE"):/work" -w /work/src \
  "$IMAGE" sleep infinity >/dev/null || { echo "ERROR: docker run" >&2; exit 1; }
# host disk guard for the whole lifetime of the container (not tied to any marker it writes)
ujc_disk_guard_start "$NAME" "$BASE"
CIP="$(ujc_container_ip "$NAME")"
echo "container_ip=$CIP" >> "$OUT/run-info.txt"

R() { docker exec -u 0 "$NAME" sh -c "$1"; }
R 'mkdir -m 0700 /var/ujc-probe && chown -R scanner:scanner /work /home/scanner' || exit 1
R 'find /home/scanner /work /tmp -xdev -type f -printf "%p %s %T@\n" 2>/dev/null | sort > /var/ujc-probe/before.txt'
docker exec -d -u 0 "$NAME" sh -c 'inotifywait -m -r -q --timefmt %T --format "%T %e %w%f" \
  -e create,modify,moved_to,delete,attrib /home/scanner /work /tmp 2>&1 | head -c 209715200 > /var/ujc-probe/inotify.log'
docker exec -d -u 0 "$NAME" sh -c 'tcpdump -i any -nn -p -s 256 -c 1000000 -Z root -w /var/ujc-probe/network.pcap > /var/ujc-probe/tcpdump.log 2>&1'
sleep 2

# strace as root, target via -u as user scanner; output readable only by root
STRACE='strace -f -qq -s 200 -e trace=execve,connect,openat -e signal=none -u scanner'
# every file written by strace and by the target is capped (512-byte blocks, UJC_MAX_OUTPUT_MB)
FSIZE="ulimit -f $(( ${UJC_MAX_OUTPUT_MB:-200} * 2048 ));"
if [ -n "$INSTALL" ]; then
  ujc_run "$NAME" install /work/src "$ITMO" \
    "$FSIZE env HOME=/home/scanner timeout $ITMO $STRACE -o /var/ujc-probe/strace-install.txt sh -c \"\$UJC_PROBE_CMD\"" \
    -u 0 -e "UJC_PROBE_CMD=$INSTALL"
fi
if [ "$ONLINE" = "1" ]; then
  echo "WARNING: UJC_PROBE_ONLINE=1 - the entry point keeps the network via the proxy (deviation from rule 10)" >&2
else
  ujc_disconnect_net "$NAME" || { echo "ERROR: network disconnection not proven - aborting before the entry point" >&2; exit 1; }
fi
ujc_run "$NAME" entry /work/src "$RTMO" \
  "$FSIZE env HOME=/home/scanner timeout $RTMO $STRACE -o /var/ujc-probe/strace-entry.txt sh -c \"\$UJC_PROBE_CMD\"" \
  -u 0 -e "UJC_PROBE_CMD=$ENTRY"
sleep 2

R 'pkill tcpdump; pkill inotifywait; sleep 1
   find /home/scanner /work /tmp -xdev -type f -printf "%p %s %T@\n" 2>/dev/null | sort > /var/ujc-probe/after.txt
   tcpdump -nn -r /var/ujc-probe/network.pcap > /var/ujc-probe/network-traffic.txt 2>/dev/null; true'

# evaluation in the container (Python), result to /var/ujc-probe/behavior-probe.md
docker exec -i -u 0 "$NAME" python3 - <<'PY'
import re, collections, os
d = "/var/ujc-probe"
def read(n):
    p = os.path.join(d, n)
    return open(p, encoding="utf-8", errors="replace").read().splitlines() if os.path.exists(p) else []
z = ["# Behavior probe\n"]
for part in ("install", "entry"):
    st = read(f"strace-{part}.txt")
    if not st:
        continue
    progs = collections.Counter()
    targets = collections.Counter()
    written = collections.Counter()
    for l in st:
        m = re.search(r'execve\("([^"]+)", \[(.*?)\]', l)
        if m and "= 0" in l[-20:] or (m and "<unfinished" in l):
            progs[(m.group(1) + " " + m.group(2).replace('", "', " ").strip('"'))[:160]] += 1
        m = re.search(r'connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), (?:inet_pton\(AF_INET6?, "|sin_addr=inet_addr\(")([^"]+)"', l)
        if m:
            targets[f"{m.group(2)}:{m.group(1)}"] += 1
        m = re.search(r'connect\(\d+, \{sa_family=AF_UNIX, sun_path="([^"]+)"', l)
        if m:
            targets[f"unix:{m.group(1)}"] += 1
        m = re.search(r'openat\([^,]+, "([^"]+)", ([A-Z_|]+)', l)
        if m and re.search(r"O_WRONLY|O_RDWR|O_CREAT", m.group(2)) and "= -1" not in l:
            written[m.group(1)] += 1
    z.append(f"## Phase {part}\n")
    z.append(f"### Started programs ({len(progs)})\n")
    z.extend(f"- `{p}` ({n}x)" for p, n in progs.most_common(80))
    z.append(f"\n### Connection targets according to strace ({len(targets)})\n")
    z.extend(f"- `{p}` ({n}x)" for p, n in targets.most_common(80)) if targets else z.append("- none")
    outside = [p for p in written if not p.startswith(("/work/", "/home/scanner/", "/tmp/", "/dev/", "/proc/"))]
    z.append(f"\n### Files opened for writing ({len(written)}; outside home/work/tmp: {len(outside)})\n")
    z.extend(f"- `{p}` (OUTSIDE)" for p in outside[:40])
    z.extend(f"- `{p}`" for p in sorted(p for p in written if p not in outside)[:80])
    if len(written) > 120:
        z.append(f"- ... {len(written)} in total (strace-{part}.txt)")
    z.append("")
before = {l.split(" ")[0]: l for l in read("before.txt")}
after = {l.split(" ")[0]: l for l in read("after.txt")}
new = sorted(set(after) - set(before)); gone = sorted(set(before) - set(after))
changed = sorted(p for p in set(before) & set(after) if before[p] != after[p])
z.append("## Files before/after (home, /work, /tmp)\n")
z.append(f"new: {len(new)}, changed: {len(changed)}, deleted: {len(gone)}\n")
for title, items in (("new", new), ("changed", changed), ("deleted", gone)):
    if items:
        z.append(f"### {title}\n")
        z.extend(f"- `{p}`" for p in items[:60])
        if len(items) > 60:
            z.append(f"- ... {len(items) - 60} more (before.txt/after.txt)")
        z.append("")
net = collections.Counter()
for l in read("network-traffic.txt"):
    m = re.search(r" > ([0-9a-f.:]+)\.(\d+): ", l)
    if m:
        net[f"{m.group(1)}:{m.group(2)}"] += 1
z.append("## Network traffic according to tcpdump (target:port, packets)\n")
z.extend(f"- `{p}` ({n})" for p, n in net.most_common(40)) if net else z.append("- none")
z.append("\nTarget 3128 is the egress proxy; what it forwarded or blocked is in the proxy log (egress.log).")
open(os.path.join(d, "behavior-probe.md"), "w", encoding="utf-8", newline="\n").write("\n".join(z) + "\n")
PY

# guard the copy to the host: the observation folder must stay below UJC_MAX_WORK_GB
PROBE_MB="$(docker exec -u 0 "$NAME" du -sm /var/ujc-probe 2>/dev/null | cut -f1)"
if [ -n "$PROBE_MB" ] && [ "$PROBE_MB" -le $(( ${UJC_MAX_WORK_GB:-20} * 1024 )) ] 2>/dev/null; then
  docker cp "$NAME:/var/ujc-probe/." "$OUT/" >/dev/null 2>&1
else
  echo "ERROR: observation data ${PROBE_MB:-?} MB above the limit or not measurable - not copied to the host" >&2
fi
BLOCKED="$(ujc_log_end "$OUT/egress.log" "$CIP")"
{
  echo
  echo "## Egress proxy"
  echo
  echo "Requests: $(grep -vc '^#' "$OUT/egress.log"), blocked: ${BLOCKED:-0} (egress.log, egress.log.blocked)."
  echo "Blocked attempts are a finding: where did the tool want to go, and why?"
} >> "$OUT/behavior-probe.md"
echo "end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/run-info.txt"
echo "done: $OUT/behavior-probe.md"
grep -H '^exit=' "$OUT"/install.txt "$OUT"/entry.txt 2>/dev/null | sed 's/^/  /'
