#!/usr/bin/env bash
# Scanner run against a quarantine clone with the scanner image ujc-scanner.
#
# Usage (Git Bash; start longer runs as a background process):
#   tools/scan.sh <quarantine-path> <output-dir>
#     <quarantine-path>  quarantine/<name> or a package extract under .claudex-tmp/<name>/...
#                        (nothing else - never projects, the user profile, forks)
#     <output-dir>       e.g. .claudex-tmp/<name>/scan (created; its content is replaced).
#                        Must be a folder BELOW <checker>/.claudex-tmp/ or below $TEMP/$TMP, must not
#                        contain the target and not lie in the scan work folder; anything else exits 2.
#
# Environment (optional):
#   UJC_SCANNER_IMAGE   image (default: newest local ujc-scanner:<date>)
#   UJC_SCAN_ONLINE=0   skip phase 2 (osv-scanner, trivy, grype via the proxy)
#   UJC_SEMGREP_RULES   subfolders of the local Semgrep rules (default see scan_inside.sh);
#                       only [A-Za-z0-9_/ -] allowed, passed into the container
#   UJC_SCAN_TIMEOUT    timeout per phase in seconds (default 3600)
#
# Flow:
#   Phase 1 offline  --network none: gitleaks, trufflehog (without verification), semgrep (local
#                    rules), bandit, guarddog, zizmor (offline), actionlint, hadolint, shellcheck, ruff, radon,
#                    lizard, jscpd, syft (SBOM)
#   Phase 2 online   internal network + egress proxy with list "scanner" (tools/egress/allowlist-scanner.txt):
#                    osv-scanner, trivy, grype (database fetches only); afterwards the previous
#                    list is restored; proxy log to <output>/egress.log
#   Phase 3 summary  scan-summary.md (without network)
# Protection: target mounted read-only, results go to $TEMP first (never a project folder in the
# container), read-only root file system, no capabilities, no-new-privileges, limits,
# user scanner (uid 10001), no tokens. Console output is ASCII only (result files contain raw tool
# output). Exit status: 0 = run complete; 1 = a phase failed, the summary is missing or the egress
# check failed; 2 = usage. Tool exit codes that mean errors are listed as WARNING (and in the summary);
# findings exit codes (gitleaks/osv-scanner/bandit 1, shellcheck 123) are not errors.
set -u
export MSYS_NO_PATHCONV=1
# shellcheck source=lib_sandbox.sh
. "$(dirname "$0")/lib_sandbox.sh"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <quarantine-path> <output-dir>" >&2
  exit 2
fi
CHECKER="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"
SRC="$(cd "$1" 2>/dev/null && { pwd -W 2>/dev/null || pwd; })" || { echo "ERROR: path not found: $1" >&2; exit 2; }
case "$SRC" in
  "$CHECKER"/quarantine/?*|"$CHECKER"/.claudex-tmp/?*) ;;
  *) echo "ERROR: only paths under $CHECKER/quarantine/ or .claudex-tmp/ are scanned (was: $SRC)" >&2; exit 2 ;;
esac

# --- output directory: its content is DELETED, so it must lie in a scratch area
WINPATHS=0
(cd / && pwd -W) >/dev/null 2>&1 && WINPATHS=1
# resolve_path <path> - absolute path, also for folders that do not exist yet (no ".." allowed)
resolve_path() {
  local p="${1//\\//}" rest="" np d
  case "/$p/" in */../*) return 1;; esac
  while [ ! -d "$p" ]; do
    rest="/$(basename "$p")$rest"
    np="$(dirname "$p")"
    [ "$np" = "$p" ] && return 1
    p="$np"
  done
  d="$(cd "$p" && { pwd -W 2>/dev/null || pwd; })" || return 1
  printf '%s%s' "$d" "$rest"
}
# below <path> <dir> - path is strictly inside dir (case-insensitive on Windows)
below() {
  local a="$1" b="$2"
  if [ "$WINPATHS" = 1 ]; then a="${a,,}"; b="${b,,}"; fi
  case "$a" in "$b"/?*) return 0;; esac
  return 1
}
SCRATCH_TEMP="$(cd "${TEMP:-/tmp}" 2>/dev/null && { pwd -W 2>/dev/null || pwd; })"
SCRATCH_TMP=""
[ -n "${TMP:-}" ] && SCRATCH_TMP="$(cd "$TMP" 2>/dev/null && { pwd -W 2>/dev/null || pwd; })"
DEST="$(resolve_path "$2")" || { echo "ERROR: output directory cannot be resolved (no \"..\"): $2" >&2; exit 2; }
ALLOWED=0
for base in "$CHECKER/.claudex-tmp" "$SCRATCH_TEMP" "$SCRATCH_TMP"; do
  [ -n "$base" ] && below "$DEST" "$base" && ALLOWED=1
done
if [ "$ALLOWED" != 1 ]; then
  echo "ERROR: output directory must be below $CHECKER/.claudex-tmp/ or below the temp folder (was: $DEST)" >&2
  exit 2
fi
if [ "$DEST" = "$SRC" ] || below "$DEST" "$SRC" || below "$SRC" "$DEST"; then
  echo "ERROR: output directory and target must not contain each other" >&2; exit 2
fi
for base in "$SCRATCH_TEMP" "$SCRATCH_TMP"; do
  if [ -n "$base" ] && { below "$DEST" "$base/ujc-scan" || [ "$DEST" = "$base/ujc-scan" ]; }; then
    echo "ERROR: output directory must not lie in the scan work folder" >&2; exit 2
  fi
done
mkdir -p "$DEST" || exit 2
DEST="$(cd "$DEST" && { pwd -W 2>/dev/null || pwd; })"

SEMOPT=()
if [ -n "${UJC_SEMGREP_RULES:-}" ]; then
  case "$UJC_SEMGREP_RULES" in
    *[!A-Za-z0-9_/\ -]*) echo "ERROR: UJC_SEMGREP_RULES may only contain [A-Za-z0-9_/ -]" >&2; exit 2;;
  esac
  SEMOPT=(-e "UJC_SEMGREP_RULES=$UJC_SEMGREP_RULES")
fi

IMAGE="${UJC_SCANNER_IMAGE:-}"
if [ -z "$IMAGE" ]; then
  TAG="$(docker image ls ujc-scanner --format '{{.Tag}}' | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' | sort -r | head -n 1)"
  [ -n "$TAG" ] || { echo "ERROR: no image ujc-scanner:<date> - run tools/setup.sh first" >&2; exit 1; }
  IMAGE="ujc-scanner:$TAG"
fi
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE")" || { echo "ERROR: image $IMAGE missing" >&2; exit 1; }
TMO="${UJC_SCAN_TIMEOUT:-3600}"

# names and folders are unique per run (PID): even if two runs overlapped, neither could reach the
# other's containers or mounted output
NAME="ujc-scan-$(basename "$SRC" | tr -d '\n' | tr -c 'a-zA-Z0-9_.-' '-')-$$"
TMP="${TEMP:-/tmp}/ujc-scan/$(basename "$SRC")-$$"
# one sandbox run at a time (shared proxy, names and folders) - held until the script ends
ujc_run_lock "scan $SRC" || exit 1
trap 'ujc_run_unlock' EXIT
# (PIDs can be reused: containers with these names must be provably gone before $TMP is created)
for ph in offline online summary; do ujc_remove_proven "$NAME-$ph" || exit 1; done
rm -rf "${TMP:?}"
mkdir -p "$TMP"
OUT="$(cd "$TMP" && { pwd -W 2>/dev/null || pwd; })"
INFO="target=$SRC image=$IMAGE id=$IMAGE_ID begin=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ -d "$SRC/.git" ] && INFO="$INFO commit=$(git -C "$SRC" rev-parse HEAD 2>/dev/null)"
echo "$INFO" > "$OUT/run-info.txt"

# shared hardening of all scanner containers
# shellcheck disable=SC2054  # the commas belong to the --tmpfs option values
HARDEN=(--cap-drop ALL --security-opt no-new-privileges --read-only
      --tmpfs /tmp:rw,size=4g --tmpfs /home/scanner:rw,uid=10001,gid=10001,size=1g
      --memory "${UJC_MEMORY:-6g}" --cpus "${UJC_CPUS:-4}" --pids-limit "${UJC_PIDS:-512}"
      --label ujc.sandbox=1 "${SEMOPT[@]}"
      --log-driver json-file --log-opt max-size=50m --log-opt max-file=1
      -v "$(ujc_host_path "$SRC"):/src:ro" -v "$(ujc_host_path "$OUT"):/out")

# Host-only control folder (never mounted into a container): phase logs and notes the host writes
# while a container could still have planted symlinks in $TMP. Copied to the destination at the end.
CTL="$TMP.ctl"
rm -rf "${CTL:?}"
mkdir -p "$CTL"
MAXWORK_MB=$(( ${UJC_MAX_WORK_GB:-20} * 1024 ))

# phase <name> <network options ...> - start the container detached, wait for the done marker.
# Order matters: the container is removed BEFORE the host reads or writes anything in $TMP, and
# sanitize_out runs before control returns - a symlink planted during the phase cannot redirect a
# host write. The output folder is watched against UJC_MAX_WORK_GB (host disk).
phase() {
  local ph="$1"; shift
  local note="" n=0
  ujc_remove_proven "$NAME-$ph" || exit 1
  docker run -d --name "$NAME-$ph" "${HARDEN[@]}" "$@" "$IMAGE" /opt/ujc/scan_inside.sh "$ph" > /dev/null \
    || { echo "ERROR: docker run ($ph)" >&2; return 1; }
  local deadline=$(( $(date +%s) + TMO ))
  while [ ! -f "$TMP/.done-$ph" ]; do
    if ! docker ps -q --filter "name=^$NAME-$ph\$" | grep -q .; then break; fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "WARNING: phase $ph aborted after $TMO s" >&2
      note="phase-$ph exit=TIMEOUT"
      break
    fi
    n=$((n + 1))
    if [ $((n % 6)) -eq 0 ] && [ "$(du -sm "$TMP" 2>/dev/null | cut -f1)" -gt "$MAXWORK_MB" ] 2>/dev/null; then
      echo "WARNING: phase $ph aborted - output folder above ${UJC_MAX_WORK_GB:-20} GB" >&2
      note="phase-$ph exit=DISK_LIMIT"
      break
    fi
    sleep 5
  done
  # container output can be produced endlessly: Docker keeps at most 50 MB (--log-opt), the host
  # copy is capped as well
  docker logs "$NAME-$ph" 2>&1 | head -c 52428800 > "$CTL/phase-$ph.log"
  [ "$(wc -c < "$CTL/phase-$ph.log")" -lt 52428800 ] || echo "[truncated at 50 MB by scan.sh]" >> "$CTL/phase-$ph.log"
  # Removal must be PROVEN before the host touches $TMP again: a container that is still running
  # could plant a symlink after sanitize_out. On doubt the whole run ends here (exit, not return -
  # callers must not write into $TMP).
  ujc_remove_proven "$NAME-$ph" || { echo "ERROR: not touching the output of $NAME-$ph ($TMP)" >&2; exit 1; }
  sanitize_out
  [ -z "$note" ] || echo "$note" >> "$TMP/exitcodes.txt"
  [ -f "$TMP/.done-$ph" ] || { echo "ERROR: phase $ph without done marker ($CTL/phase-$ph.log)" >&2; return 1; }
}
trap 'docker rm -f "$NAME-offline" "$NAME-online" "$NAME-summary" >/dev/null 2>&1; ujc_run_unlock' EXIT
FAIL=0

# sanitize_out - after EVERY container phase, before the host reads or appends anything in $TMP:
# only regular files and folders may stay. A symlink planted by the scanned repository (via a
# tool) as e.g. egress.log or exitcodes.txt would otherwise redirect the host's next write or read
# to an arbitrary host file. The phase containers run with --rm, so nothing changes afterwards.
sanitize_out() {
  local odd
  odd="$(find "$TMP" ! -type f ! -type d -print 2>/dev/null | LC_ALL=C tr -c '[:print:]\n' '?')"
  if [ -n "$odd" ]; then
    echo "WARNING: non-regular files in the container output removed (finding - who planted them?):" >&2
    echo "$odd" | sed 's/^/  WARNING: /' >&2
    find "$TMP" ! -type f ! -type d -delete 2>/dev/null
  fi
}

echo "Phase 1: offline ($IMAGE)"
phase offline --network none || exit 1
sanitize_out

if [ "${UJC_SCAN_ONLINE:-1}" = "1" ]; then
  STATE="${UJC_EGRESS_STATE:-${TEMP:-/tmp}/ujc-egress-state}"
  PREVIOUS="$(cat "$STATE/list.txt" 2>/dev/null || echo standard)"
  echo "Phase 2: online via the egress proxy (list scanner)"
  if ujc_egress_prepare scanner; then
    ujc_log_start
    # databases (trivy, grype) in the named volume - kept between runs
    # (teardown: setup.sh --remove); UJC_SCAN_DB_VOLUME= (empty) = no volume
    DBV="${UJC_SCAN_DB_VOLUME-ujc-scanner-db}"
    DBOPT=()
    [ -n "$DBV" ] && DBOPT=(-v "$DBV:/db")
    phase online --network "$UJC_NET" "${UJC_PROXY_ENV[@]}" "${DBOPT[@]}" || FAIL=1
    sanitize_out
    BLOCKED="$(ujc_log_end "$OUT/egress.log")"
    echo "egress blocked=${BLOCKED:-0}" >> "$OUT/run-info.txt"
  else
    echo "phase-online exit=EGRESS_CHECK_FAILED" >> "$TMP/exitcodes.txt"
    echo "ERROR: egress check failed - online phase not run" >&2
    FAIL=1
  fi
  # shellcheck disable=SC2086
  "$UJC_TOOLS_DIR/egress/setup.sh" $PREVIOUS > /dev/null || echo "WARNING: egress list not restored ($PREVIOUS)" >&2
  [ "$PREVIOUS" = "scanner" ] || [ "$(cat "$STATE/list.txt" 2>/dev/null)" = "$PREVIOUS" ] \
    || echo "WARNING: active egress list is not \"$PREVIOUS\" again" >&2
fi

echo "Phase 3: summary"
phase summary --network none || exit 1
sanitize_out
[ -s "$OUT/scan-summary.md" ] || { echo "ERROR: scan-summary.md is missing" >&2; FAIL=1; }
if [ -f "$OUT/egress.log" ]; then
  {
    echo
    echo "## Egress (phase 2)"
    echo
    N_ALL="$(grep -vc '^#' "$OUT/egress.log")"
    N_BLOCKED="$(grep -c . "$OUT/egress.log.blocked" 2>/dev/null)"
    echo "Requests: ${N_ALL:-0}, blocked: ${N_BLOCKED:-0}."
    echo "Blocked targets are missing from tools/egress/allowlist-scanner.txt - check whether a scanner needs a new source"
    echo "(then add it deliberately, reason in the commit) or whether something else wanted to get out."
  } >> "$OUT/scan-summary.md"
fi

# --- tool exit codes: findings are normal, everything else non-zero is an error
ERRLIST=""
while IFS=' ' read -r tool res; do
  [ -n "$tool" ] || continue
  code="${res#exit=}"
  [ "$code" = "0" ] && continue
  case "$tool:$code" in
    gitleaks:1|gitleaks-history:1|osv-scanner:1|bandit:1|shellcheck:123) continue;;
  esac
  ERRLIST="$ERRLIST$tool exit=$code"$'\n'
done < "$OUT/exitcodes.txt"
if [ -n "$ERRLIST" ]; then
  echo "WARNING: tools with exit codes that mean errors (read their logs; findings are NOT complete):" >&2
  printf '%s' "$ERRLIST" | LC_ALL=C tr -c '[:print:]\n' '?' | sed 's/^/  WARNING: /' >&2
  {
    echo
    echo "## Scanner errors"
    echo
    echo "These tools ended with an exit code that means an error (not findings); their results are incomplete:"
    echo
    printf '%s' "$ERRLIST" | LC_ALL=C tr -c '[:print:]\n' '?' | sed 's/^/- /'
  } >> "$OUT/scan-summary.md"
fi
echo "end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/run-info.txt"

# nothing but regular files and folders may leave the container output (no symlinks, devices, ...)
sanitize_out

# results to the destination (content replaced); done markers stay in the temp folder
find "$DEST" -mindepth 1 -delete 2>/dev/null
cp -r "$TMP"/. "$DEST"/
cp "$CTL"/* "$DEST"/ 2>/dev/null
rm -f "$DEST"/.done-*
rm -rf "${TMP:?}" "${CTL:?}"
echo "done: $DEST/scan-summary.md"
# container-written text: no control characters to the terminal
LC_ALL=C tr -c '[:print:]\n' '?' < "$DEST/exitcodes.txt" | sed 's/^/  /'
[ "$FAIL" = 0 ] || echo "ERROR: scan incomplete (failed phase, missing summary or egress check) - see messages above" >&2
exit "$FAIL"
