#!/usr/bin/env bash
# Sets up the sandbox of the ujc-security-checker - one entry point for everything, idempotent.
#
# Usage (Git Bash on Windows, bash on Linux/macOS; on Windows also tools/setup.ps1):
#   tools/setup.sh              set up, or complete missing parts
#   tools/setup.sh --check      report status only, change nothing (exit 0 = everything ready)
#   tools/setup.sh --rebuild    recreate the proxy and rebuild the image without cache
#   tools/setup.sh --remove     tear down: proxy, network, scanner images, DB volume, state
#
# Steps (fixed order; setup stops at the first failure, --check runs all steps and reports every
# failure):
#   1 prerequisites  docker (daemon reachable, Linux containers, amd64), git, bash, shellcheck
#   2 egress         internal network ujc-sandbox-net + proxy ujc-sandbox-proxy (egress/setup.sh)
#   3 check          egress/check.sh - abort unless all checks pass
#   4 image          build the scanner image ujc-scanner:<YYYY-MM-DD> unless one matches the repo
#   5 tools          start every tool in the image once without network (version)
#   6 scripts        shell scripts and git hooks: syntax (bash -n), shellcheck (severity warning);
#                    base images present by digest
#
# Local settings (optional, gitignored): private/environment.conf, private/egress.conf
# (lines UJC_<NAME>=<value>; see tools/lib_sandbox.sh). Output is ASCII only.
set -u
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
# shellcheck source=lib_sandbox.sh
. "$HERE/lib_sandbox.sh"

MODE=setup
for a in "$@"; do
  case "$a" in
    --check) MODE=check ;;
    --rebuild) MODE=rebuild ;;
    --remove) MODE=remove ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "ERROR: unknown option $a (--check | --rebuild | --remove)" >&2; exit 2 ;;
  esac
done

IMG_REPO=ujc-scanner
DB_VOLUME=ujc-scanner-db
STATE="${UJC_EGRESS_STATE:-${TEMP:-/tmp}/ujc-egress-state}"
# Base images of the container scripts (must match the defaults in the scripts)
BASE_IMAGES=(
  "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
  "node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20"
  "ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
)
# tool -> version command (step 5)
TOOLS=(
  "gitleaks|gitleaks version" "trufflehog|trufflehog --version" "osv-scanner|osv-scanner --version"
  "trivy|trivy --version" "syft|syft version" "grype|grype version" "actionlint|actionlint -version"
  "hadolint|hadolint --version" "shellcheck|shellcheck --version" "scorecard|scorecard version" "semgrep|semgrep --version"
  "guarddog|guarddog --version" "bandit|bandit --version" "zizmor|zizmor --version"
  "ruff|ruff --version" "radon|radon --version" "lizard|lizard --version" "jscpd|jscpd --version"
  "knip|knip --version" "snyk-agent-scan|snyk-agent-scan --help >/dev/null && /opt/venv/agent-scan/bin/pip show snyk-agent-scan | grep ^Version" "node|node --version"
  "strace|strace -V" "tcpdump|tcpdump --version" "inotifywait|command -v inotifywait >/dev/null && dpkg -s inotify-tools | grep ^Version"
)

FAILED=0
ok()    { echo "OK      $*"; }
warn()  { echo "WARNING $*"; }
fail()  { echo "ERROR   $*"; FAILED=1; }
step()  { echo; echo "== $*"; }
abort() { [ "$MODE" = "check" ] && return 0; echo; echo "ABORT: $*" >&2; exit 1; }

# Hash over the image build context (file contents, LF-normalised, sorted)
context_hash() {
  (cd "$HERE/scanner-image" && find . -type f \( -name Dockerfile -o -name '*.sh' -o -name '*.txt' -o -name '*.in' -o -name '*.json' \) \
     ! -name 'VERSIONS.md' | LC_ALL=C sort | while IFS= read -r f; do
       printf '%s\n' "$f"; tr -d '\r' < "$f"
     done) | sha256_stdin | cut -c1-16
}
sha256_stdin() { # sha256sum (Linux, Git Bash) or shasum (macOS); fails if neither exists
  if command -v sha256sum >/dev/null 2>&1; then sha256sum
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256
  else echo "ERROR: neither sha256sum nor shasum found" >&2; return 1
  fi
}
matching_image() { # prints the newest ujc-scanner image whose context label matches
  local k="$1" t
  for t in $(docker image ls "$IMG_REPO" --format '{{.Tag}}' | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' | sort -r); do
    if [ "$(docker image inspect -f '{{index .Config.Labels "ujc.context"}}' "$IMG_REPO:$t" 2>/dev/null)" = "$k" ]; then
      echo "$IMG_REPO:$t"; return 0
    fi
  done
  return 1
}

# ------------------------------------------------------------------ teardown
if [ "$MODE" = "remove" ]; then
  step "Teardown"
  OTHERS="$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$UJC_NET" 2>/dev/null | tr ' ' '\n' | grep -v -x -e "$UJC_PROXY_NAME" -e '' || true)"
  [ -z "$OTHERS" ] || { echo "ERROR: still attached to network $UJC_NET: $(echo $OTHERS) - stop them first" >&2; exit 1; }
  docker rm -f "$UJC_PROXY_NAME" >/dev/null 2>&1 && ok "proxy $UJC_PROXY_NAME removed" || ok "proxy was not present"
  docker network rm "$UJC_NET" >/dev/null 2>&1 && ok "network $UJC_NET removed" || ok "network was not present"
  for t in $(docker image ls "$IMG_REPO" --format '{{.Repository}}:{{.Tag}}'); do
    docker image rm "$t" >/dev/null 2>&1 && ok "image $t removed" || warn "image $t not removed (in use?)"
  done
  docker volume rm "$DB_VOLUME" >/dev/null 2>&1 && ok "volume $DB_VOLUME removed" || ok "volume was not present"
  # only a recognisable state folder of egress/setup.sh is deleted (UJC_EGRESS_STATE may point anywhere)
  case "$(basename "$STATE")" in
    ujc-egress-state*) rm -rf "${STATE:?}" && ok "state $STATE removed" ;;
    *) if [ -f "$STATE/list.txt" ] && [ -z "$(find "$STATE" -mindepth 1 -maxdepth 1 ! -name list.txt ! -name allowlist.txt ! -name allowlist.new ! -name clients.txt ! -name reconfigure.txt 2>/dev/null)" ]; then
         rm -rf "${STATE:?}" && ok "state $STATE removed"
       else
         warn "state $STATE NOT removed: does not look like an egress state folder - delete it by hand"
       fi ;;
  esac
  echo "Deliberately kept: proxy logs (${UJC_EGRESS_LOG:-\$TEMP/ujc-egress-log}) as evidence,"
  echo "base images (python/node/squid), result folders under \$TEMP/ujc-*. No prune over the whole engine."
  exit 0
fi

# ------------------------------------------------------------------ 1 prerequisites
step "1 Prerequisites"
command -v docker >/dev/null 2>&1 && ok "docker: $(docker --version 2>/dev/null)" || { fail "docker not found"; abort "Docker missing"; }
if docker info >/dev/null 2>&1; then
  OST="$(docker info -f '{{.OSType}}/{{.Architecture}}')"
  SV="$(docker version -f '{{.Server.Version}}')"
  ok "Docker daemon reachable, engine $SV, $OST"
  case "$OST" in linux/x86_64|linux/amd64) ;; *) fail "image is built for linux/amd64 (found: $OST)"; abort "wrong platform";; esac
  case "${SV%%.*}" in ''|*[!0-9]*) ;; *) [ "${SV%%.*}" -ge 28 ] || { fail "Docker engine >= 28 required (isolated gateway of the sandbox network)"; abort "Docker engine too old"; } ;; esac
else
  fail "Docker daemon not reachable (Docker Desktop started?)"; abort "Docker not running"
fi
command -v git >/dev/null 2>&1 && ok "git: $(git --version)" || { fail "git not found"; abort "git missing"; }
ok "bash ${BASH_VERSION}"
# 4.4: before it, "${arr[@]}" of an empty array is an unbound variable under set -u (the scripts
# pass optional option arrays that way). macOS ships bash 3.2 - install a current one (brew install bash).
{ [ "${BASH_VERSINFO[0]}" -gt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 4 ]; }; } \
  || { fail "bash >= 4.4 required (macOS: brew install bash)"; abort "bash too old"; }
if command -v shellcheck >/dev/null 2>&1; then
  ok "shellcheck $(shellcheck --version 2>/dev/null | sed -n 's/^version: //p' | tr -d '\r')"
else
  fail "shellcheck not found (winget install koalaman.shellcheck | apt install shellcheck | brew install shellcheck)"
  abort "shellcheck missing"
fi
command -v coderabbit >/dev/null 2>&1 && ok "coderabbit CLI: $(coderabbit --version 2>/dev/null) (only for cr_full_review.sh)" \
  || warn "coderabbit CLI not found (only needed for cr_full_review.sh)"
command -v gh >/dev/null 2>&1 && ok "gh: $(gh --version | head -n 1) (only for cr_full_review.sh, visibility check)" \
  || warn "gh not found (cr_full_review.sh then cannot check visibility)"
for f in environment.conf egress.conf; do
  [ -f "$UJC_CHECKER_DIR/private/$f" ] && ok "local settings private/$f read" || ok "private/$f not present (optional)"
done

# ------------------------------------------------------------------ 2 egress
step "2 Egress network and proxy"
if [ "$MODE" = "check" ]; then
  if [ "$(docker network inspect -f '{{.Internal}}' "$UJC_NET" 2>/dev/null)" = "true" ]; then ok "network $UJC_NET present, --internal"; else fail "network $UJC_NET missing or not --internal"; fi
  if [ "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$UJC_NET" 2>/dev/null)" = "isolated" ]; then
    ok "network $UJC_NET: host has no address on the bridge (gateway isolated)"
  else
    fail "network $UJC_NET: gateway not isolated - tools/setup.sh recreates it"
  fi
  if docker ps --format '{{.Names}}' | grep -qx "$UJC_PROXY_NAME"; then
    ok "proxy $UJC_PROXY_NAME running, active list: $(cat "$STATE/list.txt" 2>/dev/null || echo '?')"
    # .Image of a container is the image ID, not the registry digest - compare with the ID of the
    # pinned reference (they differ for multi-arch images)
    WANT="$(docker image inspect -f '{{.Id}}' "${BASE_IMAGES[2]}" 2>/dev/null)"
    [ "$(docker inspect -f '{{.Image}}' "$UJC_PROXY_NAME")" = "$WANT" ] && ok "proxy image = pinned digest" \
      || warn "proxy is not running the pinned image ($WANT) - tools/setup.sh --rebuild"
  else
    fail "proxy $UJC_PROXY_NAME not running"
  fi
else
  REBUILD_OPT=(); [ "$MODE" = "rebuild" ] && REBUILD_OPT=(--rebuild)
  if "$HERE/egress/setup.sh" "${REBUILD_OPT[@]}" standard; then ok "network and proxy ready (list standard)"; else fail "egress/setup.sh"; abort "egress setup failed"; fi
fi

# ------------------------------------------------------------------ 3 check
step "3 Egress check (check.sh)"
if [ "$MODE" = "check" ] && ! docker ps --format '{{.Names}}' | grep -qx "$UJC_PROXY_NAME"; then
  fail "skipped - proxy not running"
elif "$HERE/egress/check.sh"; then
  ok "check.sh passed"
else
  fail "check.sh did NOT pass"
  abort "egress is not tight - setting up nothing further (output above)"
fi

# ------------------------------------------------------------------ 4 image
step "4 Scanner image"
CONTEXT="$(context_hash)"
# an empty or short hash would match an image with an empty label - never continue with it
case "$CONTEXT" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) fail "context hash of tools/scanner-image could not be computed ('$CONTEXT')"; abort "no context hash"; CONTEXT="" ;;
esac
IMG="$( [ -n "$CONTEXT" ] && matching_image "$CONTEXT" || true)"
if [ -n "$IMG" ] && [ "$MODE" != "rebuild" ]; then
  ok "$IMG matches the repository state (context $CONTEXT, id $(docker image inspect -f '{{.Id}}' "$IMG" | cut -c1-19))"
elif [ "$MODE" = "check" ]; then
  fail "no ujc-scanner image for the repository state (context $CONTEXT) - tools/setup.sh builds it"
else
  DATE="$(date +%Y-%m-%d)"
  IMG="$IMG_REPO:$DATE"
  CACHE=(); [ "$MODE" = "rebuild" ] && CACHE=(--no-cache)
  BUILD_LOG="${TEMP:-/tmp}/ujc-scanner-build.txt"
  echo "building $IMG (context $CONTEXT, log $BUILD_LOG) - takes a few minutes, needs network for the downloads"
  if docker build "${CACHE[@]}" --build-arg "IMAGE_DATE=$DATE" --build-arg "UJC_CONTEXT=$CONTEXT" \
       -t "$IMG" "$HERE/scanner-image" > "$BUILD_LOG" 2>&1; then
    ok "$IMG built (id $(docker image inspect -f '{{.Id}}' "$IMG" | cut -c1-19))"
  else
    fail "docker build failed - last lines:"; tail -n 15 "$BUILD_LOG"
    abort "image build failed"
  fi
fi

# ------------------------------------------------------------------ 5 tools
step "5 Tools in the image (without network)"
if [ -n "$IMG" ] && docker image inspect "$IMG" >/dev/null 2>&1; then
  for w in "${TOOLS[@]}"; do
    name="${w%%|*}"; cmd="${w#*|}"
    v="$(docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges "$IMG" sh -c "$cmd" 2>&1)"
    rc=$?
    v="$(echo "$v" | grep -iE 'version|[0-9]+\.[0-9]+' | grep -viE 'network error|failed to download|copyright|usage' | head -n 1 | tr -cd '[:print:]' | cut -c1-70)"
    if [ $rc -eq 0 ]; then ok "$(printf '%-16s' "$name") $v"; else fail "$name does not start (rc=$rc)"; fi
  done
else
  fail "skipped - no image"
fi

# ------------------------------------------------------------------ 6 container scripts
step "6 Container scripts"
# paths relative to tools/
SCRIPTS=(lib_sandbox.sh container_test_python.sh container_test_npm.sh scan.sh behavior_probe.sh
         cr_full_review.sh setup.sh egress/setup.sh egress/check.sh scanner-image/generate_locks.sh
         scanner-image/scan_inside.sh ../.githooks/_run_gate.sh ../.githooks/pre-commit
         ../.githooks/pre-push)
for s in "${SCRIPTS[@]}"; do
  if bash -n "$HERE/$s" 2>/dev/null; then ok "bash -n $s"; else fail "syntax error in $s"; fi
done
if command -v shellcheck >/dev/null 2>&1; then
  if SC_OUT="$(cd "$HERE" && shellcheck -x -P SCRIPTDIR -S warning -f gcc "${SCRIPTS[@]}" 2>&1)"; then
    ok "shellcheck (severity warning): ${#SCRIPTS[@]} scripts clean"
  else
    fail "shellcheck reports findings:"; echo "$SC_OUT" | tr -d '\r' | head -n 40
  fi
else
  fail "shellcheck not found - see step 1"
fi
for b in "${BASE_IMAGES[@]}"; do
  if docker image inspect "$b" >/dev/null 2>&1; then
    ok "base image present: ${b%%@*}@${b#*@sha256:}" | cut -c1-90
  elif [ "$MODE" = "check" ]; then
    warn "base image missing: ${b%%@*} (pulled during setup)"
  elif docker pull -q "$b" >/dev/null 2>&1; then
    ok "base image pulled: ${b%%@*}"
  else
    fail "base image cannot be pulled: $b"
  fi
done

echo
if [ $FAILED -eq 0 ]; then
  echo "RESULT: sandbox ready (image ${IMG:-?})"
  exit 0
fi
echo "RESULT: NOT ready - see messages above"
exit 1
