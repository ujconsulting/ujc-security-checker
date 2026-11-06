# shellcheck shell=bash
# Shared building blocks of the sandbox container scripts (container_test_*.sh, behavior_probe.sh,
# scan.sh). Sourced with `. tools/lib_sandbox.sh`; plain Bash functions, no side effects when
# sourced. Output is ASCII only.
#
# Mandatory rule (CLAUDE.md): sandbox containers NEVER run in the default bridge network. The
# install phase runs only in the internal network ujc-sandbox-net via the egress proxy; afterwards
# the network is disconnected completely and the disconnection is verified.

UJC_NET=ujc-sandbox-net
UJC_PROXY_NAME=ujc-sandbox-proxy
UJC_PROXY_URL=http://ujc-sandbox-proxy:3128
UJC_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && { pwd -W 2>/dev/null || pwd; })"
UJC_CHECKER_DIR="$(cd "$UJC_TOOLS_DIR/.." && { pwd -W 2>/dev/null || pwd; })"

# Local settings from private/ (gitignored, not part of the public repository).
# Only lines UJC_<NAME>=<value> are read; nothing is executed as code.
# Environment variables that are already set take precedence.
#   private/environment.conf  e.g. UJC_PROTECTED_PATHS=<path>;<path>  (never create work dirs there)
#   private/egress.conf       e.g. UJC_EGRESS_LAN_TARGET=<ip>:<port>   (LAN target for check.sh)
ujc_load_private() {
  local f line k v
  for f in "$UJC_CHECKER_DIR/private/environment.conf" "$UJC_CHECKER_DIR/private/egress.conf"; do
    [ -f "$f" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%$'\r'}"
      case "$line" in UJC_*=*) ;; *) continue ;; esac
      k="${line%%=*}"; v="${line#*=}"
      case "$k" in *[!A-Z0-9_]*) continue ;; esac
      [ -n "${!k:-}" ] || export "$k=$v"
    done < "$f"
  done
}
ujc_load_private

# host_path <path> - path for `docker run -v` (Git Bash: Windows path; Linux/macOS: unchanged)
ujc_host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi
}

# Proxy environment for docker run/exec (Python, npm, Node, curl, uv)
# shellcheck disable=SC2034  # used by the scripts that source this library
UJC_PROXY_ENV=(
  -e "HTTP_PROXY=$UJC_PROXY_URL" -e "HTTPS_PROXY=$UJC_PROXY_URL"
  -e "http_proxy=$UJC_PROXY_URL" -e "https_proxy=$UJC_PROXY_URL"
  -e "NO_PROXY=localhost,127.0.0.1" -e "no_proxy=localhost,127.0.0.1"
)
# shellcheck disable=SC2034  # used by the scripts that source this library
UJC_NPM_PROXY_ENV=(
  -e "npm_config_proxy=$UJC_PROXY_URL" -e "npm_config_https_proxy=$UJC_PROXY_URL"
  -e "NODE_USE_ENV_PROXY=1"
)

ujc_log_file() {
  local d="${UJC_EGRESS_LOG:-${TEMP:-/tmp}/ujc-egress-log}"
  echo "$d/access.log"
}

# egress_prepare [<list> ...] - setup.sh + check.sh; aborts (return 1) if check.sh does not pass
ujc_egress_prepare() {
  # Output to $OUT/egress-check.txt if an output directory is set, otherwise to the console
  local dest="${OUT:+$OUT/egress-check.txt}"
  dest="${dest:-/dev/stdout}"
  "$UJC_TOOLS_DIR/egress/setup.sh" "$@" > "$dest" 2>&1 \
    || { echo "ERROR: egress/setup.sh (output: $dest)" >&2; return 1; }
  if ! "$UJC_TOOLS_DIR/egress/check.sh" >> "$dest" 2>&1; then
    echo "ERROR: egress/check.sh did not pass - aborting (output: $dest)" >&2
    return 1
  fi
  return 0
}

# image_digest <image> - prints a reference <repo>@sha256:... (pulls the image if needed)
ujc_image_digest() {
  local img="$1"
  case "$img" in *@sha256:*) echo "$img"; return 0;; esac
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null || return 1
  local d
  d="$(docker image inspect -f '{{index .RepoDigests 0}}' "$img" 2>/dev/null)"
  [ -n "$d" ] && [ "$d" != "<no value>" ] || { echo "ERROR: no digest for $img (built locally?)" >&2; return 1; }
  echo "$d"
}

# log_start - remembers the current line count of the proxy log (start of the time window)
ujc_log_start() {
  local f; f="$(ujc_log_file)"
  UJC_LOG_LINE=$( [ -f "$f" ] && wc -l < "$f" || echo 0 )
  UJC_LOG_BEGIN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# log_end <dest-file> [<container-ip>] - excerpt since log_start; filtered by IP if given.
# Writes <dest>, <dest>.blocked (TCP_DENIED) and prints the number of blocked attempts.
ujc_log_end() {
  local dest="$1" ip="${2:-}" f; f="$(ujc_log_file)"
  {
    echo "# Proxy log $UJC_LOG_BEGIN to $(date -u +%Y-%m-%dT%H:%M:%SZ), container IP ${ip:-all}"
    if [ -f "$f" ]; then
      if [ -n "$ip" ]; then
        tail -n +"$((UJC_LOG_LINE + 1))" "$f" | awk -v ip="$ip" '$3 == ip'
      else
        tail -n +"$((UJC_LOG_LINE + 1))" "$f"
      fi
    fi
  } > "$dest"
  grep 'TCP_DENIED' "$dest" > "$dest.blocked" 2>/dev/null
  grep -c 'TCP_DENIED' "$dest" 2>/dev/null || true
}

# container_ip <name> - IP in the internal network (for the log filter)
ujc_container_ip() {
  docker inspect -f "{{with index .NetworkSettings.Networks \"$UJC_NET\"}}{{.IPAddress}}{{end}}" "$1" 2>/dev/null
}

# fetch_result <container> <container-path> <host-file> - docker cp of one result file written by
#   code under test. Refuses anything that is not a regular file on the host side afterwards
#   (docker cp copies a symlink as a symlink - reading it would follow it into the host).
ujc_fetch_result() {
  rm -f "$3"
  docker cp "$1:$2" "$3" >/dev/null 2>&1 || return 1
  if [ -L "$3" ] || [ ! -f "$3" ]; then
    rm -rf "$3"
    echo "ERROR: $2 in $1 is not a regular file (symlink?) - not used" >&2
    return 1
  fi
  return 0
}

# run <container> <name> <workdir> <timeout-s> <command> [docker-exec-options ...]
#   detached (docker exec -d): output to /tmp/ujc-out/<name>.txt in the container (capped at
#   UJC_MAX_OUTPUT_MB, default 200), last line exit=<code>, then the done marker <name>.done.
#   Polls at short intervals, copies the file to $OUT/<name>.txt, prints the exit line and
#   RETURNS the command's exit code (124 on timeout - the processes in the container are killed).
#   Reason for detaching: the time limit of the calling tool aborted long runs, and
#   `command | tail` swallows the exit code.
ujc_run() {
  local ct="$1" name="$2" wd="$3" timeout="$4" cmd="$5"; shift 5
  local blocks=$(( ${UJC_MAX_OUTPUT_MB:-200} * 2048 ))
  docker exec "$ct" sh -c 'mkdir -p /tmp/ujc-out && rm -f "/tmp/ujc-out/$1.txt" "/tmp/ujc-out/$1.done" "/tmp/ujc-out/$1.rc"' _ "$name"
  docker exec -d -w "$wd" "$@" -e "UJC_RUN_NAME=$name" -e "UJC_RUN_CMD=$cmd" -e "UJC_RUN_BLOCKS=$blocks" "$ct" sh -c '
    o="/tmp/ujc-out/$UJC_RUN_NAME"
    { ( eval "$UJC_RUN_CMD" ) 2>&1; echo "$?" > "$o.rc"; } | ( ulimit -f "$UJC_RUN_BLOCKS"; cat > "$o.txt" )
    echo "exit=$(cat "$o.rc" 2>/dev/null || echo unknown)" >> "$o.txt"
    touch "$o.done"'
  local deadline=$(( $(date +%s) + timeout + 120 )) n=0 maxmb=$(( ${UJC_MAX_WORK_GB:-20} * 1024 ))
  while ! docker exec "$ct" test -f "/tmp/ujc-out/$name.done" 2>/dev/null; do
    # host disk: the writable host folder of the container (UJC_WATCH_DIR, set by the scripts to
    # what they mount as /work) is measured every 30 s; above UJC_MAX_WORK_GB the run is stopped
    n=$((n + 1))
    if [ -n "${UJC_WATCH_DIR:-}" ] && [ $((n % 6)) -eq 0 ] \
       && [ "$(du -sm "$UJC_WATCH_DIR" 2>/dev/null | cut -f1)" -gt "$maxmb" ] 2>/dev/null; then
      echo "WARNING: $name stopped - $UJC_WATCH_DIR above ${UJC_MAX_WORK_GB:-20} GB" >&2
      docker exec -u 0 "$ct" sh -c 'kill -KILL -1' >/dev/null 2>&1
      docker exec -u 10001 "$ct" sh -c 'kill -KILL -1' >/dev/null 2>&1
      ujc_fetch_result "$ct" "/tmp/ujc-out/$name.txt" "$OUT/$name.txt" || : > "$OUT/$name.txt"
      echo "exit=DISK_LIMIT" >> "$OUT/$name.txt"
      return 125
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "WARNING: $name not finished after $timeout s - killing the processes in $ct" >&2
      # the containers run without CAP_KILL: root can only kill root's processes, so kill once
      # per user (root and scanner, uid 10001 - the target of the behavior probe)
      docker exec -u 0 "$ct" sh -c 'kill -KILL -1' >/dev/null 2>&1
      docker exec -u 10001 "$ct" sh -c 'kill -KILL -1' >/dev/null 2>&1
      ujc_fetch_result "$ct" "/tmp/ujc-out/$name.txt" "$OUT/$name.txt" || : > "$OUT/$name.txt"
      echo "exit=TIMEOUT" >> "$OUT/$name.txt"
      return 124
    fi
    sleep 5
  done
  if ! ujc_fetch_result "$ct" "/tmp/ujc-out/$name.txt" "$OUT/$name.txt"; then
    echo "exit=NO_RESULT" > "$OUT/$name.txt"
    tail -n 1 "$OUT/$name.txt"
    return 125
  fi
  local last; last="$(tail -n 1 "$OUT/$name.txt")"
  echo "$last"
  case "${last#exit=}" in
    ''|*[!0-9]*) return 125 ;;
    *) return "${last#exit=}" ;;
  esac
}

# run_lock - one sandbox run at a time on this machine (scan, container tests, behavior probe).
#   Two runs share the proxy, its log, container names and work folders; a second run could remove
#   the first one's container and plant symlinks into its output. mkdir is atomic; the lock holds
#   the PID, a lock whose process no longer exists is taken over. Released by ujc_run_unlock (trap).
UJC_RUN_LOCK="${TEMP:-/tmp}/ujc-sandbox-run.lock"
ujc_run_lock() {
  local pid age tries=0 l="$UJC_RUN_LOCK"
  while [ $tries -lt 3 ]; do
    tries=$((tries + 1))
    if mkdir "$l" 2>/dev/null; then
      # publish the owner atomically (rename), then verify the lock really is ours
      echo "$1" > "$l/what"
      echo "$$" > "$l/pid.tmp" && mv -f "$l/pid.tmp" "$l/pid"
      if [ "$(cat "$l/pid" 2>/dev/null)" = "$$" ]; then UJC_RUN_LOCK_HELD=1; return 0; fi
      echo "ERROR: sandbox run lock taken but ownership not verifiable - aborting" >&2
      return 1
    fi
    pid="$(cat "$l/pid" 2>/dev/null)"
    if [ -n "$pid" ]; then
      if kill -0 "$pid" 2>/dev/null; then
        echo "ERROR: another sandbox run is active (pid $pid, $(cat "$l/what" 2>/dev/null)) - one run at a time" >&2
        return 1
      fi
    else
      # no PID yet: another run is creating the lock right now - held, unless it is old (crash)
      # mtime: GNU stat (Linux, Git Bash) or BSD stat (macOS)
      age=$(( $(date +%s) - $(stat -c %Y "$l" 2>/dev/null || stat -f %m "$l" 2>/dev/null || date +%s) ))
      if [ "$age" -lt 60 ]; then
        echo "ERROR: another sandbox run is starting - one run at a time" >&2
        return 1
      fi
    fi
    # stale lock: renaming it away is atomic - only one caller wins, the loop then retries mkdir
    if mv "$l" "$l.stale.$$" 2>/dev/null; then
      # between the check and the rename another run may have replaced the stale lock by its own:
      # the moved directory must still be the one judged stale (same PID or still none), otherwise
      # it is put back and this run stops - never two owners
      if [ "$(cat "$l.stale.$$/pid" 2>/dev/null)" != "$pid" ]; then
        mv "$l.stale.$$" "$l" 2>/dev/null
        echo "ERROR: sandbox run lock changed owner during takeover - one run at a time" >&2
        return 1
      fi
      echo "WARNING: stale sandbox run lock (pid ${pid:-none}) removed" >&2
      rm -rf "$l.stale.$$"
    fi
  done
  echo "ERROR: cannot take the sandbox run lock" >&2
  return 1
}
ujc_run_unlock() {
  [ "${UJC_RUN_LOCK_HELD:-}" = "1" ] && [ "$(cat "$UJC_RUN_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$UJC_RUN_LOCK"
  UJC_RUN_LOCK_HELD=""
}

# remove_proven <container> - removes the container and PROVES it is gone (docker ps -a). Returns 1
#   if the removal cannot be proven - a failing docker command counts as "not removed". Callers abort
#   then: a container that still runs could keep writing into a folder the host is about to reuse
#   (planted symlinks redirect later host writes or the extraction of the next copy).
ujc_remove_proven() {
  local left
  docker rm -f "$1" >/dev/null 2>&1
  if ! left="$(docker ps -a -q --filter "name=^$1\$" 2>/dev/null)" || [ -n "$left" ]; then
    echo "ERROR: container $1 not provably removed - aborting" >&2
    return 1
  fi
  return 0
}

# disk_guard_start <container> <host-dir> - host-side watchdog in the background, independent of
#   anything the container writes (done markers can be forged by the code under test): every 30 s
#   the writable host folder is measured; above UJC_MAX_WORK_GB the container is killed. Runs until
#   the container is gone; disk_guard_stop ends it early. One guard per script run.
ujc_disk_guard_start() {
  local ct="$1" dir="$2" maxmb=$(( ${UJC_MAX_WORK_GB:-20} * 1024 ))
  (
    while docker inspect "$ct" >/dev/null 2>&1; do
      if [ "$(du -sm "$dir" 2>/dev/null | cut -f1)" -gt "$maxmb" ] 2>/dev/null; then
        echo "WARNING: $dir above ${UJC_MAX_WORK_GB:-20} GB - container $ct killed (disk guard)" >&2
        docker kill "$ct" >/dev/null 2>&1
        exit 0
      fi
      sleep 30
    done
  ) &
  UJC_DISK_GUARD_PID=$!
}
ujc_disk_guard_stop() {
  [ -n "${UJC_DISK_GUARD_PID:-}" ] && kill "$UJC_DISK_GUARD_PID" 2>/dev/null
  UJC_DISK_GUARD_PID=""
}

# disconnect_net <container> - disconnects from the internal network and verifies it:
#   no networks left on the container; no connection to pypi.org, registry.npmjs.org, or the proxy
#   by name and by IP. Writes $OUT/network.txt; return 1 if anything is still reachable.
ujc_disconnect_net() {
  local ct="$1" pip
  pip="$(docker inspect -f "{{with index .NetworkSettings.Networks \"$UJC_NET\"}}{{.IPAddress}}{{end}}" "$UJC_PROXY_NAME" 2>/dev/null)"
  [ -n "$pip" ] || { echo "ERROR: proxy IP in $UJC_NET unknown - cannot verify the disconnection" >&2; return 1; }
  docker network disconnect "$UJC_NET" "$ct" 2>/dev/null
  local nets rc
  nets="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$ct")" \
    || { echo "ERROR: docker inspect $ct failed - disconnection not verifiable" >&2; return 1; }
  {
    echo "networks_after_disconnect=[${nets% }]"
    docker exec -e "PIP=$pip" "$ct" sh -c '
      targets="pypi.org:443 registry.npmjs.org:443 ujc-sandbox-proxy:3128"
      [ -n "$PIP" ] && targets="$targets $PIP:3128"
      for t in $targets; do
        h=${t%:*}; p=${t#*:}
        if command -v python3 >/dev/null 2>&1; then
          python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 5)" "$h" "$p" >/dev/null 2>&1
        elif command -v node >/dev/null 2>&1; then
          node -e "const s=require(\"net\").connect({host:process.argv[1],port:+process.argv[2],timeout:5000},()=>process.exit(0));s.on(\"error\",()=>process.exit(1));s.on(\"timeout\",()=>process.exit(1))" "$h" "$p" >/dev/null 2>&1
        else
          echo "NO_PROBE_TOOL"; exit 0
        fi
        if [ $? -eq 0 ]; then echo "NETWORK_STILL_UP $t"; else echo "blocked $t"; fi
      done'
    echo "probe_exit=$?"
  } > "$OUT/network.txt" 2>&1
  # Evidence must be complete: the probe ran (exit 0) and reported "blocked" for all 4 targets
  rc="$(grep -c '^blocked ' "$OUT/network.txt")"
  if [ -n "${nets// /}" ] || grep -qE 'NETWORK_STILL_UP|NO_PROBE_TOOL' "$OUT/network.txt" \
     || ! grep -qx 'probe_exit=0' "$OUT/network.txt" || [ "$rc" -ne 4 ]; then
    echo "ERROR: network not provably gone after disconnecting ($OUT/network.txt)" >&2
    return 1
  fi
  echo "network_disconnected" >> "$OUT/network.txt"
  return 0
}

# check_workdir <path> [<repo-path>] - the work directory must not be inside the repository under
# test, inside the checker, or under a protected path (UJC_PROTECTED_PATHS, ";"-separated, e.g.
# the folder with all own projects - from private/environment.conf)
ujc_check_workdir() {
  local p g
  for p in "${2:-}" "$UJC_CHECKER_DIR"; do
    [ -n "$p" ] || continue
    case "$1" in "$p"|"$p"/*) echo "ERROR: work directory is inside $p" >&2; return 1;; esac
    # the other way round too: the scripts delete <workdir>/<name> - a repository below the work
    # directory could be that folder
    case "$p" in "$1"/*) echo "ERROR: $p is inside the work directory $1" >&2; return 1;; esac
  done
  local IFS=';'
  for g in ${UJC_PROTECTED_PATHS:-}; do
    g="${g%/}"
    [ -n "$g" ] || continue
    case "$1" in "$g"|"$g"/*) echo "ERROR: work directory is under a protected path ($g)" >&2; return 1;; esac
  done
  return 0
}
