#!/usr/bin/env bash
# Isolated test run for a Python fork (plus a comparison run with the upstream revision).
# Generalised from the test script of a fork hardening (October 2026).
#
# START ONLY AFTER EXPLICIT APPROVAL BY THE OWNER - the script executes package code
# (in the container, but it does execute it). The approval is bound to the exact commits:
#   UJC_TEST_APPROVAL=<fork-commit-sha>                    (without a comparison run)
#   UJC_TEST_APPROVAL=<fork-commit-sha>+<upstream-sha>     (with a comparison run)
# full 40-character SHAs; the script archives exactly these commits.
#
# Usage (Git Bash; start long runs as a background process):
#   tools/container_test_python.sh <repo-path> [<ref>] [<upstream-ref>] [<extras>]
#     <repo-path>     fork working copy, e.g. <forks>/ujc-<name>
#     <ref>           revision of the fork to test (default HEAD; committed revisions only)
#     <upstream-ref>  comparison revision (tag/SHA in the same repo); "-" = no comparison run
#     <extras>        comma list of optional extras, e.g. "mcp,pdf" ("" = none)
#
# Environment (optional):
#   UJC_TEST_WORKDIR   work directory OUTSIDE every repository (default: $TEMP/ujc-container-tests)
#   UJC_PY_IMAGE       image; without @sha256 it is resolved to its digest
#                      (default python:3.12-slim-bookworm@sha256:34386ef0...)
#   UJC_UV_VERSION     uv version for projects with uv.lock (default 0.13.0)
#   UJC_TEST_TIMEOUT   overall timeout per pytest run in seconds (default 3600)
#   UJC_INSTALL_TIMEOUT  timeout per installation in seconds (default 1800)
#   UJC_FOCUS_TESTS    additional verbose run of only these tests, e.g. "tests/test_ujc_*.py"
#   UJC_PRETEND_VERSION  for setuptools_scm/hatch-vcs projects (git archive has no .git)
#   UJC_MEMORY / UJC_CPUS / UJC_PIDS  resource limits (default 6g / 4 / 512)
#
# Protection:
# - egress precondition: tools/egress/setup.sh + check.sh (abort if check.sh does not pass)
# - copy via `git archive` (no mount of the working repository, committed files only)
# - the container only sees the copy directory; no capabilities, no-new-privileges, limits
# - network only for the installation: internal network ujc-sandbox-net, exit only via the
#   egress proxy (allowlist); afterwards the network is disconnected completely and verified
# - proxy log of the run to $OUT/egress.log (blocked attempts = finding)
# - output is ASCII only (cp1252 console)
set -u

# Git Bash would rewrite container paths like /work into Windows paths
export MSYS_NO_PATHCONV=1
# shellcheck source=lib_sandbox.sh
. "$(dirname "$0")/lib_sandbox.sh"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <repo-path> [<ref>] [<upstream-ref>|-] [<extras>]" >&2
  exit 2
fi

# pwd -W: Windows path (X:/...) under Git Bash, because native programs like git.exe no longer
# understand /d/... paths with MSYS_NO_PATHCONV=1
REPO="$(cd "$1" 2>/dev/null && { pwd -W 2>/dev/null || pwd; })" || { echo "ERROR: repository not found: $1" >&2; exit 2; }
REF="${2:-HEAD}"
UPREF="${3:--}"
EXTRAS="${4:-}"
IMAGE_IN="${UJC_PY_IMAGE:-python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258}"
UVV="${UJC_UV_VERSION:-0.13.0}"
TMO="${UJC_TEST_TIMEOUT:-3600}"
ITMO="${UJC_INSTALL_TIMEOUT:-1800}"
FOCUS="${UJC_FOCUS_TESTS:-}"

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
NAME="ujc-pytest-$(basename "$REPO" | tr -d '\n' | tr -c 'a-zA-Z0-9_.-' '-')-$$"
BASE="$CT/$(basename "$REPO")-$$"
OUT="$CT/$(basename "$REPO")-out"
# one sandbox run at a time (shared proxy, names and folders) - held until the script ends
ujc_run_lock "container_test_python $REPO" || exit 1
trap 'ujc_run_unlock' EXIT
# a container of an earlier run must be provably gone before its mounted folder is reused
ujc_remove_proven "$NAME" || exit 1
rm -rf "${BASE:?}" "${OUT:?}"
mkdir -p "$BASE/fork" "$OUT"
# host disk guard of ujc_run: this folder is mounted writable as /work (UJC_MAX_WORK_GB)
UJC_WATCH_DIR="$BASE"

# precondition: the egress environment is up and holds tight
ujc_egress_prepare standard || exit 1
IMAGE="$(ujc_image_digest "$IMAGE_IN")" || { echo "ERROR: image digest for $IMAGE_IN" >&2; exit 1; }

git -C "$REPO" archive "$SHA" | tar -x -C "$BASE/fork" || { echo "ERROR: git archive $SHA" >&2; exit 1; }
INFO="fork=$SHA"
DIRS="fork"
if [ "$UPREF" != "-" ]; then
  mkdir -p "$BASE/upstream"
  git -C "$REPO" archive "$UPSHA" | tar -x -C "$BASE/upstream" || { echo "ERROR: git archive $UPSHA" >&2; exit 1; }
  INFO="$INFO upstream=$UPSHA"
  DIRS="fork upstream"
fi
echo "$INFO image=$IMAGE extras=$EXTRAS uv=$UVV network=$UJC_NET proxy=$UJC_PROXY_URL" > "$OUT/run-info.txt"

EXTRA_ARGS=""
if [ -n "$EXTRAS" ]; then
  for e in $(echo "$EXTRAS" | tr ',' ' '); do EXTRA_ARGS="$EXTRA_ARGS --extra $e"; done
fi
ENV_ARGS=()
[ -n "${UJC_PRETEND_VERSION:-}" ] && ENV_ARGS=(-e "SETUPTOOLS_SCM_PRETEND_VERSION=$UJC_PRETEND_VERSION")

ujc_remove_proven "$NAME" || exit 1
trap 'ujc_disk_guard_stop; docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "${BASE:?}"; ujc_run_unlock' EXIT
ujc_log_start
docker run -d --name "$NAME" --label ujc.sandbox=1 --log-driver json-file --log-opt max-size=50m --log-opt max-file=1 \
  --network "$UJC_NET" "${UJC_PROXY_ENV[@]}" \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory "${UJC_MEMORY:-6g}" --cpus "${UJC_CPUS:-4}" --pids-limit "${UJC_PIDS:-512}" \
  "${ENV_ARGS[@]}" \
  -v "$(ujc_host_path "$BASE"):/work" -w /work \
  "$IMAGE" sleep infinity >/dev/null || { echo "ERROR: docker run" >&2; exit 1; }
# host disk guard for the whole lifetime of the container (not tied to any marker it writes)
ujc_disk_guard_start "$NAME" "$BASE"
CIP="$(ujc_container_ip "$NAME")"
echo "container_ip=$CIP" >> "$OUT/run-info.txt"

# Phase 1: installation (internal network, via the proxy only), one venv each for fork and upstream
ujc_run "$NAME" uv /work "$ITMO" 'pip install -q --disable-pip-version-check "uv==$UVV"' -e "UVV=$UVV" \
  || { ujc_log_end "$OUT/egress.log" "$CIP" >/dev/null; echo "ERROR: installing uv failed - aborting ($OUT/uv.txt)" >&2; exit 1; }
TESTDIRS=""
for d in $DIRS; do
  # uv.lock present: exactly per lock file; otherwise pip into a venv (project + pytest)
  if ujc_run "$NAME" "install-$d" "/work/$d" "$ITMO" '
    if [ -f uv.lock ]; then
      UV_LINK_MODE=copy uv sync --frozen --all-groups $EXTRA_ARGS
    else
      python -m venv .venv && . .venv/bin/activate && \
      pip install -q ".${EXTRAS:+[$EXTRAS]}" pytest
    fi' -e "EXTRA_ARGS=$EXTRA_ARGS" -e "EXTRAS=$EXTRAS"; then
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
  # full output to the file (no tail, so that no exit code is lost);
  # pytest-timeout is not a project dependency, hence the overall timeout via timeout(1)
  ujc_run "$NAME" "pytest-$d" "/work/$d" "$TMO" '
    if [ -f uv.lock ]; then RUN="uv run --no-sync python"; else RUN=".venv/bin/python"; fi
    timeout "$TMO" $RUN -m pytest -q -p no:cacheprovider -o addopts="" -rfE' -e "TMO=$TMO"
done

if [ -n "$FOCUS" ]; then
  ujc_run "$NAME" pytest-focus /work/fork "$TMO" '
    if [ -f uv.lock ]; then RUN="uv run --no-sync python"; else RUN=".venv/bin/python"; fi
    $RUN -m pytest -q -p no:cacheprovider -o addopts="" -rs $FOCUS' -e "FOCUS=$FOCUS"
fi

# proxy log once more after the tests (stragglers of the install phase)
BLOCKED="$(ujc_log_end "$OUT/egress.log" "$CIP")"

echo "done: $OUT"
grep -H "^exit=" "$OUT"/install-*.txt "$OUT"/pytest-*.txt 2>/dev/null | sed 's/^/  /'
echo "  egress: $(grep -vc '^#' "$OUT/egress.log") requests, blocked: ${BLOCKED:-0} (finding if > 0: $OUT/egress.log.blocked)"
