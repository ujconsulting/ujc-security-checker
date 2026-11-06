#!/usr/bin/env bash
# Regenerates the lock files of the scanner image (Python: uv pip compile with hashes, wheels only;
# npm: package-lock.json without install scripts). Runs in throwaway containers in the internal
# network ujc-sandbox-net via the egress proxy - never in the default bridge network.
#
# Usage (Git Bash, from any folder):
#   tools/scanner-image/generate_locks.sh
# Afterwards: read the diff of the lock files (new packages? new sources?), rebuild the image,
# update VERSIONS.md. Inputs: lock/*.in (one pinned line per tool), npm/package.json.
#
# The containers only see a copy of the inputs under $TEMP, never the project tree.
set -u
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
EGRESS="$(cd "$HERE/../egress" && pwd)"
PY_IMAGE="${UJC_LOCK_PY_IMAGE:-python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258}"
NODE_IMAGE="${UJC_LOCK_NODE_IMAGE:-node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20}"
UV_VERSION="${UJC_LOCK_UV:-0.13.0}"
PX=http://ujc-sandbox-proxy:3128

"$EGRESS/setup.sh" standard || { echo "ERROR: egress/setup.sh" >&2; exit 1; }
"$EGRESS/check.sh" || { echo "ERROR: egress/check.sh did not pass - aborting" >&2; exit 1; }

WD="${TEMP:-/tmp}/ujc-scanner-locks"
rm -rf "${WD:?}"
mkdir -p "$WD/lock" "$WD/npm"
cp "$HERE"/lock/*.in "$WD/lock/"
cp "$HERE/npm/package.json" "$WD/npm/"
WDW="$(cd "$WD" && { pwd -W 2>/dev/null || pwd; })"

PROXY_ENV=(-e "HTTP_PROXY=$PX" -e "HTTPS_PROXY=$PX" -e "http_proxy=$PX" -e "https_proxy=$PX" -e "NO_PROXY=localhost,127.0.0.1")
LIMITS=(--cap-drop ALL --security-opt no-new-privileges --memory 2g --cpus 2 --pids-limit 256)

# Python: wheels only (--no-build), so that no build backend of foreign sdists runs
docker run --rm --network ujc-sandbox-net "${LIMITS[@]}" "${PROXY_ENV[@]}" -e "UVV=$UV_VERSION" \
  -v "$WDW/lock:/lock" -w /lock "$PY_IMAGE" sh -c '
    pip install -q --disable-pip-version-check --only-binary=:all: "uv==$UVV" >/dev/null || exit 1
    rc=0
    for f in *.in; do
      n="${f%.in}"
      uv pip compile --quiet --no-build --generate-hashes --no-header --python-version 3.12 \
        -o "$n.txt" "$f" || { echo "ERROR: $f"; rc=1; }
    done
    exit $rc' || { echo "ERROR: Python locks" >&2; exit 1; }

# npm: lock file only, no installation, no scripts
docker run --rm --network ujc-sandbox-net "${LIMITS[@]}" "${PROXY_ENV[@]}" \
  -e "npm_config_proxy=$PX" -e "npm_config_https_proxy=$PX" \
  -v "$WDW/npm:/npm" -w /npm "$NODE_IMAGE" sh -c '
    npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null' \
  || { echo "ERROR: npm lock" >&2; exit 1; }

cp "$WD"/lock/*.txt "$HERE/lock/" || { echo "ERROR: copying the Python lock files failed (results kept in $WD)" >&2; exit 1; }
cp "$WD/npm/package-lock.json" "$HERE/npm/" || { echo "ERROR: copying package-lock.json failed (results kept in $WD)" >&2; exit 1; }
rm -rf "${WD:?}"
echo "OK: lock files under $HERE/lock and $HERE/npm regenerated - read the diff, then build the image"
