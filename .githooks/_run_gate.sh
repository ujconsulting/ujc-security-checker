#!/bin/sh
# Shared part of the git hooks in .githooks/ (POSIX sh, ASCII output).
#   _run_gate.sh <hook-name> [--history] [--staged] [--pushed] -- <hook arguments>
# 1. runs the public/private gate tools/public_check.py (exit 0 required)
#    --pushed (pre-push): check the trees of the commits being pushed (--rev <sha> per ref line
#    on stdin, deletions skipped), never the work tree; no usable ref line -> --rev HEAD.
# 2. chains to the hook that would have run without core.hooksPath=.githooks:
#    UJC_CHAINED_HOOKS_PATH, otherwise the global/system core.hooksPath, otherwise
#    .git/hooks/<hook-name>. The chained hook gets the same arguments and stdin.
hook="$1"; shift
gate_args=""
pushed=""
while [ "$1" = "--history" ] || [ "$1" = "--staged" ] || [ "$1" = "--pushed" ]; do
  if [ "$1" = "--pushed" ]; then pushed=1; else gate_args="${gate_args:+$gate_args }$1"; fi
  shift
done
[ "$1" = "--" ] && shift

root=$(git rev-parse --show-toplevel) || exit 2
here="$root/.githooks"

# pre-push passes the refs on stdin: keep a copy for the chained hook
stdin_file=""
if [ "$hook" = "pre-push" ]; then
  stdin_file=$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/ujc-pre-push.$$")
  cat > "$stdin_file"
  trap 'rm -f "$stdin_file"' EXIT INT TERM
fi

if [ -n "$pushed" ]; then
  # stdin lines: <local ref> <local sha> <remote ref> <remote sha>; a malformed line fails closed
  rev_args=""
  while read -r lref lsha _rref _rsha || [ -n "$lref$lsha" ]; do
    [ -n "$lref$lsha" ] || continue
    case "$lsha" in
      ""|*[!0-9a-fA-F]*)
        echo "ERROR: $hook: unreadable ref line on stdin - gate not run, aborting" >&2
        exit 1 ;;
    esac
    case "$lsha" in
      *[!0]*) rev_args="$rev_args --rev $lsha" ;;   # all zeros = deleting a ref, nothing pushed
    esac
  done < "$stdin_file"
  [ -n "$rev_args" ] || rev_args=" --rev HEAD"
  gate_args="${gate_args:+$gate_args }${rev_args# }"
fi

py=""
for cand in "${PYTHON:-}" python3 python py; do
  [ -n "$cand" ] || continue
  if "$cand" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
    py="$cand"; break
  fi
done
if [ -z "$py" ]; then
  echo "ERROR: $hook: Python 3.10+ not found (set PYTHON=<interpreter>) - gate not run, aborting" >&2
  exit 1
fi

echo "$hook: public/private gate (tools/public_check.py $gate_args)" >&2
# shellcheck disable=SC2086
"$py" "$root/tools/public_check.py" $gate_args >&2
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ERROR: $hook blocked by tools/public_check.py (exit $rc). Fix the findings above." >&2
  exit 1
fi

# --- chain to the previous hook
prev="${UJC_CHAINED_HOOKS_PATH:-}"
if [ -z "$prev" ]; then
  prev=$(git config --global --get core.hooksPath 2>/dev/null || true)
  [ -n "$prev" ] || prev=$(git config --system --get core.hooksPath 2>/dev/null || true)
fi
if [ -n "$prev" ]; then
  # shellcheck disable=SC2088  # literal "~/" from git config, expanded by hand
  case "$prev" in "~/"*) prev="$HOME/${prev#\~/}" ;; esac
  case "$prev" in /*|[A-Za-z]:*) ;; *) prev="$root/$prev" ;; esac
  target="$prev/$hook"
else
  target="$(git rev-parse --git-common-dir)/hooks/$hook"
  case "$target" in /*|[A-Za-z]:*) ;; *) target="$root/$target" ;; esac
fi
# A configured previous hook must be usable; only "no previous hook" is fine.
if [ ! -e "$target" ]; then
  # nothing to chain to (the hook directory may exist without this hook)
  if [ -n "$prev" ] && [ ! -d "$prev" ]; then
    echo "ERROR: $hook: configured hooks path '$prev' is not a directory - cannot chain, aborting" >&2
    exit 1
  fi
  exit 0
fi
if [ ! -f "$target" ] || [ ! -x "$target" ]; then
  echo "ERROR: $hook: previous hook '$target' exists but is not an executable file - aborting" >&2
  exit 1
fi
target_dir=$(cd "$(dirname "$target")" 2>/dev/null && pwd -P) || target_dir=""
if [ -z "$target_dir" ]; then
  echo "ERROR: $hook: directory of the previous hook '$target' cannot be resolved - aborting" >&2
  exit 1
fi
here_dir=$(cd "$here" && pwd -P)
# never call ourselves again
if [ "$target_dir" = "$here_dir" ]; then
  exit 0
fi
if [ -n "$stdin_file" ]; then
  "$target" "$@" < "$stdin_file"
else
  "$target" "$@"
fi
exit $?
