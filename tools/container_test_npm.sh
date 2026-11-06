#!/usr/bin/env bash
# Isolated test and rebuild run for an npm fork (counterpart of container_test_python.sh).
# Created during a fork hardening (October 2026): there, files built at runtime ran
# (dist/, bridge/*.cjs) and were patched by hand until approval. The rebuild in the container
# shows whether the hand patches match what the build produces from src/.
#
# START ONLY AFTER EXPLICIT APPROVAL BY THE OWNER - the script executes package code
# (npm ci with install scripts, tests, build - in the container, but it does execute it).
# The approval is bound to the exact commits (full 40-character SHAs):
#   UJC_TEST_APPROVAL=<fork-commit-sha>                    (without a comparison run)
#   UJC_TEST_APPROVAL=<fork-commit-sha>+<upstream-sha>     (with a comparison run)
#
# Usage (Git Bash; start long runs as a background process):
#   tools/container_test_npm.sh <repo-path> [<ref>] [<upstream-ref>|-]
#
# Environment (optional):
#   UJC_TEST_WORKDIR     work directory OUTSIDE every repository (default: $TEMP/ujc-container-tests)
#   UJC_NODE_IMAGE       image; without @sha256 it is resolved to its digest
#                        (default node:24-bookworm-slim@sha256:d6aa754f...; mind the engines field)
#   UJC_TEST_TIMEOUT     overall timeout per test run in seconds (default 3600)
#   UJC_INSTALL_TIMEOUT  timeout per installation in seconds (default 1800)
#   UJC_NPM_TEST_CMD     test command (default "npm test"; e.g. "npx vitest run")
#   UJC_NPM_IGNORE_SCRIPTS=1   npm ci --ignore-scripts (install scripts of dependencies off)
#   UJC_NPM_BUILD=1      after the tests `npm run build` (without network) and diff of the bundles
#   UJC_BUNDLE_DIRS      folders/files the build produces and that were patched by hand
#                        (default "dist bridge"); diff hand patch vs. rebuild to $OUT/bundle-diff-*.txt
#   UJC_MEMORY / UJC_CPUS / UJC_PIDS  resource limits (default 8g / 4 / 1024)
#
# Protection as in the Python script: egress precondition (setup.sh + check.sh), git archive, only
# the copy mounted, no capabilities, no-new-privileges, limits, network only for `npm ci` in the
# internal network via the egress proxy, then disconnected completely and verified, proxy log to
# $OUT/egress.log. Output is ASCII only.
set -u
export MSYS_NO_PATHCONV=1
# shellcheck source=lib_sandbox.sh
. "$(dirname "$0")/lib_sandbox.sh"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <repo-path> [<ref>] [<upstream-ref>|-]" >&2
  exit 2
fi

REPO="$(cd "$1" 2>/dev/null && { pwd -W 2>/dev/null || pwd; })" || { echo "ERROR: repository not found: $1" >&2; exit 2; }
REF="${2:-HEAD}"
UPREF="${3:--}"
IMAGE_IN="${UJC_NODE_IMAGE:-node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20}"
TMO="${UJC_TEST_TIMEOUT:-3600}"
ITMO="${UJC_INSTALL_TIMEOUT:-1800}"
TESTCMD="${UJC_NPM_TEST_CMD:-npm test}"
BUNDLES="${UJC_BUNDLE_DIRS:-dist bridge}"
CI_FLAGS=""
[ "${UJC_NPM_IGNORE_SCRIPTS:-0}" = "1" ] && CI_FLAGS="--ignore-scripts"

# approval: bound to the resolved commits, not to a (movable) ref
SHA="$(git -C "$REPO" rev-parse --verify "$REF^{commit}" 2>/dev/null)" || { echo "ERROR: unknown ref: $REF" >&2; exit 2; }
WANT="$SHA"
if [ "$UPREF" != "-" ]; then
  UPSHA="$(git -C "$REPO" rev-parse --verify "$UPREF^{commit}" 2>/dev/null)" || { echo "ERROR: unknown ref: $UPREF" >&2; exit 2; }
  WANT="$SHA+$UPSHA"
fi
if [ "${UJC_TEST_APPROVAL:-}" != "$WANT" ]; then
  echo "ERROR: no approval. The container test executes package code and only runs after" >&2
  echo "       explicit approval by the owner for exactly these commits:" >&2
  echo "       UJC_TEST_APPROVAL=$WANT $0 ..." >&2
  exit 3
fi

CT="${UJC_TEST_WORKDIR:-${TEMP:-/tmp}/ujc-container-tests}"
CT="$(mkdir -p "$CT" && cd "$CT" && { pwd -W 2>/dev/null || pwd; })" || { echo "ERROR: cannot create work directory" >&2; exit 2; }
ujc_check_workdir "$CT" "$REPO" || exit 2

# container name and mounted work folder are unique per run (PID): overlapping runs cannot reach
# each other's container or folder. The results folder OUT keeps its stable name.
NAME="ujc-npmtest-$(basename "$REPO" | tr -d '\n' | tr -c 'a-zA-Z0-9_.-' '-')-$$"
BASE="$CT/$(basename "$REPO")-$$"
OUT="$CT/$(basename "$REPO")-out"
# comparison base OUTSIDE the container mount: code under test must not be able to change it
HAND="$CT/$(basename "$REPO")-hand-patched-$$"
# one sandbox run at a time (shared proxy, names and folders) - held until the script ends
ujc_run_lock "container_test_npm $REPO" || exit 1
trap 'ujc_run_unlock' EXIT
# a container of an earlier run must be provably gone before its mounted folder is reused
ujc_remove_proven "$NAME" || exit 1
rm -rf "${BASE:?}" "${OUT:?}" "${HAND:?}"
mkdir -p "$BASE/fork" "$OUT"
# host disk guard of ujc_run: this folder is mounted writable as /work (UJC_MAX_WORK_GB)
UJC_WATCH_DIR="$BASE"

# precondition: the egress environment is up and holds tight
ujc_egress_prepare standard || exit 1
IMAGE="$(ujc_image_digest "$IMAGE_IN")" || { echo "ERROR: image digest for $IMAGE_IN" >&2; exit 1; }

# git archive includes all TRACKED files - also built bundles that are listed in .gitignore
# but checked in (typically: dist/, bridge/)
git -C "$REPO" archive "$SHA" | tar -x -C "$BASE/fork" || { echo "ERROR: git archive $SHA" >&2; exit 1; }
INFO="fork=$SHA"
DIRS="fork"
if [ "$UPREF" != "-" ]; then
  mkdir -p "$BASE/upstream"
  git -C "$REPO" archive "$UPSHA" | tar -x -C "$BASE/upstream" || { echo "ERROR: git archive $UPSHA" >&2; exit 1; }
  INFO="$INFO upstream=$UPSHA"
  DIRS="fork upstream"
fi
echo "$INFO image=$IMAGE test=\"$TESTCMD\" build=${UJC_NPM_BUILD:-0} network=$UJC_NET proxy=$UJC_PROXY_URL" > "$OUT/run-info.txt"

# save the hand-patched bundles before any build (comparison base)
if [ "${UJC_NPM_BUILD:-0}" = "1" ]; then
  mkdir -p "$HAND"
  for b in $BUNDLES; do
    [ -e "$BASE/fork/$b" ] && mkdir -p "$(dirname "$HAND/$b")" && cp -r "$BASE/fork/$b" "$HAND/$b"
  done
fi

ujc_remove_proven "$NAME" || exit 1
trap 'ujc_disk_guard_stop; docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "${BASE:?}" "${HAND:?}"; ujc_run_unlock' EXIT
ujc_log_start
docker run -d --name "$NAME" --label ujc.sandbox=1 --log-driver json-file --log-opt max-size=50m --log-opt max-file=1 \
  --network "$UJC_NET" "${UJC_PROXY_ENV[@]}" "${UJC_NPM_PROXY_ENV[@]}" \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory "${UJC_MEMORY:-8g}" --cpus "${UJC_CPUS:-4}" --pids-limit "${UJC_PIDS:-1024}" \
  -v "$(ujc_host_path "$BASE"):/work" -w /work \
  "$IMAGE" sleep infinity >/dev/null || { echo "ERROR: docker run" >&2; exit 1; }
# host disk guard for the whole lifetime of the container (not tied to any marker it writes)
ujc_disk_guard_start "$NAME" "$BASE"
CIP="$(ujc_container_ip "$NAME")"
echo "container_ip=$CIP" >> "$OUT/run-info.txt"

# Phase 1: installation (internal network, via the proxy only), exactly per package-lock.json
TESTDIRS=""
for d in $DIRS; do
  if ujc_run "$NAME" "install-$d" "/work/$d" "$ITMO" \
    'npm ci --no-audit --no-fund $CI_FLAGS' -e "CI_FLAGS=$CI_FLAGS"; then
    TESTDIRS="$TESTDIRS $d"
  else
    # a failed or timed-out installation is not tested - its results would be meaningless
    echo "ERROR: installation of $d failed or timed out - no tests for $d ($OUT/install-$d.txt)" >&2
  fi
done
case " $TESTDIRS " in *" fork "*) ;; *)
  ujc_log_end "$OUT/egress.log" "$CIP" >/dev/null
  echo "ERROR: the fork could not be installed - aborting" >&2; exit 1 ;;
esac

# Phase 2: disconnect the network and verify (pypi/npm directly, proxy by name and IP)
BLOCKED="$(ujc_log_end "$OUT/egress.log" "$CIP")"
if ! ujc_disconnect_net "$NAME"; then
  echo "ERROR: aborting before the tests" >&2
  exit 1
fi

for d in $TESTDIRS; do
  ujc_run "$NAME" "test-$d" "/work/$d" "$TMO" 'timeout "$TMO" $TESTCMD' \
    -e "TMO=$TMO" -e "TESTCMD=$TESTCMD" -e CI=1
done

# Phase 3 (optional): rebuild without network, diff against the hand patches
if [ "${UJC_NPM_BUILD:-0}" = "1" ]; then
  ujc_run "$NAME" build-fork /work/fork "$TMO" 'npm run build' -e CI=1
  for b in $BUNDLES; do
    [ -e "$HAND/$b" ] || continue
    tag="$(echo "$b" | tr '/' '_')"
    # source maps and compiled tests are regenerated by the rebuild and not maintained by hand
    diff -r -u --exclude='*.map' --exclude='__tests__' "$HAND/$b" "$BASE/fork/$b" > "$OUT/bundle-diff-$tag.txt" 2>&1
    echo "$b: $(grep -c '^[-+][^-+]' "$OUT/bundle-diff-$tag.txt") changed lines" >> "$OUT/bundle-diff-summary.txt"
  done
fi

BLOCKED="$(ujc_log_end "$OUT/egress.log" "$CIP")"

echo "done: $OUT"
grep -H "^exit=" "$OUT"/install-*.txt "$OUT"/test-*.txt "$OUT"/build-*.txt 2>/dev/null | sed 's/^/  /'
[ -f "$OUT/bundle-diff-summary.txt" ] && sed 's/^/  /' "$OUT/bundle-diff-summary.txt"
echo "  egress: $(grep -vc '^#' "$OUT/egress.log") requests, blocked: ${BLOCKED:-0} (finding if > 0: $OUT/egress.log.blocked)"
exit 0
