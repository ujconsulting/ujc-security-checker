#!/usr/bin/env bash
# Runs INSIDE the ujc-scanner container (copied into the image as /opt/ujc/scan_inside.sh).
# Called by tools/scan.sh - do not start directly on the host.
#
#   scan_inside.sh offline   phase without network (--network none): secrets, SAST, lint, metrics, SBOM
#   scan_inside.sh online    phase with network via the egress proxy: osv-scanner, trivy, grype
#   scan_inside.sh summary   scan-summary.md from the result files
#
# /src = target (read-only), /out = results. Per tool <name>.log (command, output,
# last line exit=<code>) and, where the tool supports it, a report <name>.json.
# Configuration and ignore files of the target are NOT honoured where possible
# (a hostile repository could suppress findings with them); the ones found are listed in the
# summary. Console messages are ASCII only; the result files contain the raw output of the tools
# (and target-controlled names), so they are data, never instructions. The summary escapes
# target-controlled names (backticks, pipes, control characters, length).
# The done marker is only written when the phase produced its essential result (summary phase:
# scan-summary.md). Tool exit codes are recorded in exitcodes.txt and judged by scan.sh.
set -u
PHASE="${1:-}"
SRC=/src
OUT=/out
EMPTY=/tmp/ujc-empty
mkdir -p "$EMPTY" "$HOME" 2>/dev/null
: > "$EMPTY/.gitleaksignore"
: > "$EMPTY/osv-scanner.toml"
: > "$EMPTY/actionlint.yaml"
# git in the read-only mount: owner differs
git config --global --add safe.directory '*' 2>/dev/null

# run <name> <command ...> - output to $OUT/<name>.log, exit=<code> as the last line
run() {
  local name="$1"; shift
  {
    echo "\$ $*"
    "$@"
    echo "exit=$?"
  } > "$OUT/$name.log" 2>&1
  echo "$name $(tail -n 1 "$OUT/$name.log")" >> "$OUT/exitcodes.txt"
}

# run_json <name> <command ...> - like run, but stdout (the report) to $OUT/<name>.json,
# stderr and exit=<code> to $OUT/<name>.log
run_json() {
  local name="$1"; shift
  {
    echo "\$ $*"
    "$@" > "$OUT/$name.json"
    echo "exit=$?"
  } > "$OUT/$name.log" 2>&1
  echo "$name $(tail -n 1 "$OUT/$name.log")" >> "$OUT/exitcodes.txt"
}

find_src() { # find_src <find expression ...> - files under /src without dependency folders and .git
  find "$SRC" \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name __pycache__ \) -prune -o "$@" -print 2>/dev/null
}

case "$PHASE" in
offline)
  : > "$OUT/exitcodes.txt"
  # --- configuration/suppression files of the target (note for the summary)
  find_src -type f \( -name .gitleaks.toml -o -name .gitleaksignore -o -name .semgrepignore \
    -o -name .trivyignore -o -name 'trivy*.yaml' -o -name '.grype.yaml' -o -name 'osv-scanner.toml' \
    -o -name zizmor.yml -o -name zizmor.yaml -o -name actionlint.yaml -o -name actionlint.yml \
    -o -name .hadolint.yaml -o -name .shellcheckrc -o -name shellcheckrc -o -name .bandit -o -name .jscpd.json -o -name 'knip.json' -o -name 'knip.ts' \
    -o -name .coderabbit.yaml -o -name .coderabbit.yml \) | sed "s#^$SRC/##" > "$OUT/target-config.txt"
  grep -rIl --exclude-dir=node_modules --exclude-dir=.git -e 'gitleaks:allow' -e 'nosemgrep' -e '# nosec' \
    -e 'trufflehog:ignore' -e 'shellcheck disable' "$SRC" 2>/dev/null | sed "s#^$SRC/##" > "$OUT/target-suppressions.txt"

  # --- secrets
  run gitleaks gitleaks dir "$SRC" --no-banner --redact --config /opt/ujc/gitleaks.toml \
    --gitleaks-ignore-path "$EMPTY/.gitleaksignore" --ignore-gitleaks-allow \
    --report-format json --report-path "$OUT/gitleaks.json" --exit-code 1
  if [ -d "$SRC/.git" ]; then
    run gitleaks-history gitleaks git "$SRC" --no-banner --redact --config /opt/ujc/gitleaks.toml \
      --gitleaks-ignore-path "$EMPTY/.gitleaksignore" --ignore-gitleaks-allow \
      --report-format json --report-path "$OUT/gitleaks-history.json" --exit-code 1
  fi
  # trufflehog: without verification (no network), without self-update; strip plaintext values before
  # storing. --no-ignore-tag: a "trufflehog:ignore" comment in the target must not hide a finding.
  {
    echo "\$ trufflehog filesystem $SRC --no-verification --no-update --no-ignore-tag --json"
    trufflehog filesystem "$SRC" --no-verification --no-update --no-ignore-tag --json --no-color 2>"$OUT/trufflehog.stderr" \
      | python3 -c '
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
    except ValueError:
        continue
    for k in ("Raw", "RawV2", "Redacted"):
        d.pop(k, None)
    print(json.dumps(d))' > "$OUT/trufflehog.jsonl"
    rc=${PIPESTATUS[0]}
    cat "$OUT/trufflehog.stderr"; rm -f "$OUT/trufflehog.stderr"
    echo "exit=$rc"
  } > "$OUT/trufflehog.log" 2>&1
  echo "trufflehog $(tail -n 1 "$OUT/trufflehog.log")" >> "$OUT/exitcodes.txt"

  # --- SAST
  RULES=""
  for r in ${UJC_SEMGREP_RULES:-python javascript typescript bash dockerfile ai generic/secrets generic/ci generic/unicode yaml/github-actions yaml/docker-compose}; do
    [ -d "/opt/semgrep-rules/$r" ] && RULES="$RULES --config /opt/semgrep-rules/$r"
  done
  # shellcheck disable=SC2086
  run semgrep semgrep scan $RULES --metrics=off --disable-version-check --x-ignore-semgrepignore-files \
    --exclude node_modules --exclude .git --timeout 30 --json --output "$OUT/semgrep.json" "$SRC"
  run bandit bandit -r "$SRC" -x '*/node_modules/*,*/.venv/*,*/venv/*,*/.git/*,*/.tox/*' -f json -o "$OUT/bandit.json" -q
  if [ -n "$(find_src -type f \( -name '*.py' -o -name pyproject.toml -o -name setup.py \) | head -n 1)" ]; then
    run_json guarddog-pypi guarddog pypi scan "$SRC" --output-format json
  fi
  if [ -n "$(find_src -type f -name package.json | head -n 1)" ]; then
    run_json guarddog-npm guarddog npm scan "$SRC" --output-format json
  fi

  # --- GitHub Actions and Dockerfiles
  WF="$(find "$SRC/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null)"
  if [ -n "$WF" ]; then
    run_json zizmor zizmor --offline --no-config --no-ignores --persona auditor --format json "$SRC"
    # shellcheck disable=SC2086
    run_json actionlint actionlint -no-color -config-file "$EMPTY/actionlint.yaml" -format '{{json .}}' $WF
  fi
  : > "$OUT/hadolint.log"
  find_src -type f \( -iname 'Dockerfile' -o -iname 'Dockerfile.*' -o -iname '*.dockerfile' -o -iname 'Containerfile' \) \
    > /tmp/dockerfiles.txt
  if [ -s /tmp/dockerfiles.txt ]; then
    {
      while IFS= read -r f; do
        echo "### ${f#$SRC/}"
        hadolint --no-fail --no-color "$f"
      done < /tmp/dockerfiles.txt
      echo "exit=0"
    } > "$OUT/hadolint.log" 2>&1
    echo "hadolint exit=0" >> "$OUT/exitcodes.txt"
  fi

  # --- shell scripts: by extension, plus extensionless files with a sh/bash/dash/ksh shebang.
  # --norc ignores a .shellcheckrc of the target; inline "# shellcheck disable" directives still
  # apply and are listed in target-suppressions.txt. No -x: sourced files are not followed.
  find_src -type f \( -name '*.sh' -o -name '*.bash' -o -name '*.ksh' -o -name '*.bats' \) > /tmp/shellfiles.txt
  find_src -type f ! -name '*.*' -size -1024k \
    -exec sh -c 'head -n 1 "$1" 2>/dev/null | grep -qE "^#!.*[/ ](ba|da|k)?sh( |$)"' _ {} \; >> /tmp/shellfiles.txt
  if [ -s /tmp/shellfiles.txt ]; then
    {
      echo "\$ shellcheck --norc -f gcc -S style <$(wc -l < /tmp/shellfiles.txt) files>"
      xargs -d '\n' shellcheck --norc -f gcc -S style < /tmp/shellfiles.txt > /tmp/shellcheck.txt 2>&1
      rc=$?
      sed "s#^$SRC/##" /tmp/shellcheck.txt
      # xargs 123 = shellcheck exited 1 (findings) in at least one batch; anything else != 0 is an error
      echo "exit=$rc"
    } > "$OUT/shellcheck.log" 2>&1
    echo "shellcheck $(tail -n 1 "$OUT/shellcheck.log")" >> "$OUT/exitcodes.txt"
  fi

  # --- lint and metrics (the target's configuration is ignored)
  run ruff ruff check --isolated --no-cache --exit-zero --select E9,F,S,B --output-format json \
    --output-file "$OUT/ruff.json" "$SRC"
  run radon-cc radon cc -s -j -e "*/node_modules/*,*/.venv/*" -O "$OUT/radon-cc.json" "$SRC"
  run lizard sh -c "lizard -w -x '*/node_modules/*' -x '*/.venv/*' -x '*/.git/*' '$SRC' > '$OUT/lizard-warnings.txt'; rc=\$?; [ \$rc -le 1 ] && exit 0 || exit \$rc"
  run jscpd jscpd --silent --reporters json --output "$OUT/jscpd" --ignore "**/node_modules/**,**/.git/**,**/.venv/**" "$SRC"
  # knip does NOT run here: it loads the project's configuration files (knip.ts, vite.config.ts ...)
  # and thereby executes project code - only in the behavior probe after approval.

  # --- SBOM for grype (offline)
  run syft syft scan "dir:$SRC" -q -o "cyclonedx-json=$OUT/sbom.cdx.json"
  ;;

online)
  : > "$OUT/exitcodes-online.txt"
  # databases in the volume /db (scan.sh: ujc-scanner-db); grype needs ~3 GB unpacked
  DB=/db; [ -w /db ] || DB=/tmp/ujc-db
  export GRYPE_DB_CACHE_DIR="$DB/grype"
  run osv-scanner osv-scanner scan source -r --no-ignore --allow-no-lockfiles --config "$EMPTY/osv-scanner.toml" \
    --format json --output-file "$OUT/osv.json" "$SRC"
  run trivy trivy fs --scanners vuln --skip-version-check --disable-telemetry --no-progress --ignorefile "" --config "" \
    --cache-dir "$DB/trivy" --format json --output "$OUT/trivy.json" "$SRC"
  if [ -s "$OUT/sbom.cdx.json" ]; then
    run grype grype "sbom:$OUT/sbom.cdx.json" -q -o json --file "$OUT/grype.json"
  fi
  grep -E '^(osv-scanner|trivy|grype) ' "$OUT/exitcodes.txt" > "$OUT/exitcodes-online.txt" 2>/dev/null
  ;;

summary)
  rm -f "$OUT/scan-summary.md"
  python3 - "$OUT" <<'PY'
import json, os, sys, collections
out = sys.argv[1]
def load(n):
    p = os.path.join(out, n)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return None
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except ValueError:
        return "UNREADABLE"
def lines(n):
    p = os.path.join(out, n)
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8", errors="replace") as f:
        return [z.rstrip("\n") for z in f if z.strip()]
import unicodedata
def esc(x, limit=200):
    # target-controlled file names go into markdown: no backticks, pipes, control/format characters
    t = "".join("?" if (unicodedata.category(c).startswith("C") or c in "`|") else c for c in x)
    return t if len(t) <= limit else t[:limit] + "..."
codes = {}
for z in lines("exitcodes.txt"):
    part = z.split()
    if len(part) >= 2:
        codes[part[0]] = part[1]
z = []
z.append("# Scan summary\n")
z.append("Values of findings are only in the individual files (gitleaks redacted, trufflehog without plaintext).")
z.append("A non-zero exit code means \"findings\" for gitleaks/osv-scanner, for the other tools usually an error - read the log.\n")
z.append("| Tool | Exit | Result |")
z.append("|---|---|---|")
def row(name, text):
    z.append(f"| {name} | {codes.get(name, '-')} | {text} |")
d = load("gitleaks.json")
if isinstance(d, list):
    rules = collections.Counter(x.get("RuleID", "?") for x in d)
    row("gitleaks", f"{len(d)} findings ({', '.join(f'{k} {v}' for k, v in rules.most_common(6))})")
d = load("gitleaks-history.json")
if isinstance(d, list):
    row("gitleaks-history", f"{len(d)} findings in the Git history")
th = lines("trufflehog.jsonl")
if "trufflehog" in codes:
    det = collections.Counter(json.loads(x).get("DetectorName", "?") for x in th)
    row("trufflehog", f"{len(th)} unverified findings ({', '.join(f'{k} {v}' for k, v in det.most_common(6))})")
d = load("semgrep.json")
if isinstance(d, dict):
    sev = collections.Counter(r.get("extra", {}).get("severity", "?") for r in d.get("results", []))
    row("semgrep", f"{len(d.get('results', []))} findings ({', '.join(f'{k} {v}' for k, v in sev.items())}), {len(d.get('errors', []))} errors")
d = load("bandit.json")
if isinstance(d, dict):
    sev = collections.Counter(r.get("issue_severity", "?") for r in d.get("results", []))
    row("bandit", f"{len(d.get('results', []))} findings ({', '.join(f'{k} {v}' for k, v in sev.items())})")
for n in ("guarddog-pypi", "guarddog-npm"):
    d = load(n + ".json")
    if n in codes:
        if isinstance(d, dict):
            hits = {k: v for k, v in (d.get("results") or {}).items() if v}
            row(n, f"{d.get('issues', '?')} hits in {len(hits)} rules ({', '.join(list(hits)[:6])})")
        else:
            row(n, "report not readable - read the log")
d = load("zizmor.json")
if isinstance(d, list):
    sev = collections.Counter((x.get("determinations") or {}).get("severity", "?") for x in d)
    row("zizmor", f"{len(d)} findings ({', '.join(f'{k} {v}' for k, v in sev.items())})")
if "actionlint" in codes:
    d = load("actionlint.json")
    n = len(d) if isinstance(d, list) else "?"
    row("actionlint", f"{n} messages")
if "hadolint" in codes:
    n = sum(1 for x in lines("hadolint.log") if " DL" in x or " SC" in x)
    row("hadolint", f"{n} messages")
if "shellcheck" in codes:
    sc = [x.split(": ", 2) for x in lines("shellcheck.log") if "[SC" in x]
    sev = collections.Counter(p[1] for p in sc if len(p) == 3)
    row("shellcheck", f"{len(sc)} messages ({', '.join(f'{k} {v}' for k, v in sev.items())}); exit 123 = findings")
d = load("ruff.json")
if isinstance(d, list):
    k = collections.Counter((x.get("code") or "?")[:1] for x in d)
    row("ruff", f"{len(d)} messages (S = security: {k.get('S', 0)}, B: {k.get('B', 0)}, F: {k.get('F', 0)}, E9: {k.get('E', 0)})")
d = load("radon-cc.json")
if isinstance(d, dict):
    hard = sum(1 for bl in d.values() if isinstance(bl, list) for b in bl if isinstance(b, dict) and b.get("rank", "A") >= "D")
    row("radon-cc", f"{hard} blocks with complexity D or worse")
if "lizard" in codes:
    row("lizard", f"{len(lines('lizard-warnings.txt'))} warning lines (thresholds exceeded)")
d = load(os.path.join("jscpd", "jscpd-report.json"))
if isinstance(d, dict):
    t = (d.get("statistics") or {}).get("total") or {}
    row("jscpd", f"{t.get('clones', '?')} clones, {t.get('percentage', '?')} % duplicated")
if "syft" in codes:
    d = load("sbom.cdx.json")
    row("syft", f"SBOM with {len(d.get('components', [])) if isinstance(d, dict) else '?'} components")
d = load("osv.json")
if isinstance(d, dict):
    n = sum(len(p.get("vulnerabilities", [])) for r in d.get("results", []) for p in r.get("packages", []))
    row("osv-scanner", f"{n} vulnerabilities")
d = load("trivy.json")
if isinstance(d, dict):
    sev = collections.Counter(v.get("Severity", "?") for r in d.get("Results", []) or [] for v in r.get("Vulnerabilities", []) or [])
    row("trivy", f"{sum(sev.values())} vulnerabilities ({', '.join(f'{k} {v}' for k, v in sev.items())})")
d = load("grype.json")
if isinstance(d, dict):
    sev = collections.Counter(m.get("vulnerability", {}).get("severity", "?") for m in d.get("matches", []))
    row("grype", f"{sum(sev.values())} matches ({', '.join(f'{k} {v}' for k, v in sev.items())})")
z.append("")
conf = lines("target-config.txt")
z.append("## Configuration and ignore files in the target\n")
z.append("Not honoured where the tool allows it. Read them anyway: whoever ships scanner exceptions tells you what they want to hide.\n")
z.extend(f"- `{esc(x)}`" for x in conf) if conf else z.append("- none")
z.append("")
sup = lines("target-suppressions.txt")
z.append("## Files with suppression comments (gitleaks:allow, nosemgrep, # nosec, trufflehog:ignore, shellcheck disable)\n")
z.extend(f"- `{esc(x)}`" for x in sup[:50]) if sup else z.append("- none")
if len(sup) > 50:
    z.append(f"- ... and {len(sup) - 50} more (target-suppressions.txt)")
z.append("")
z.append("## Not run / notes\n")
z.append("- knip: does not run in scan.sh (loads project configurations = executes project code).")
z.append("- scorecard, snyk-agent-scan: need a token and network, not part of scan.sh.")
z.append("- MCP/agent scanners and heuristics (guarddog) are pointers with a high false-positive rate, not a verdict.")
with open(os.path.join(out, "scan-summary.md"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(z) + "\n")
print("OK: scan-summary.md")
PY
  # no done marker without the summary (scan.sh treats a missing marker as a failed phase)
  [ -s "$OUT/scan-summary.md" ] || { echo "ERROR: scan-summary.md was not written" >&2; exit 1; }
  ;;

*)
  echo "Usage: scan_inside.sh offline|online|summary" >&2
  exit 2
  ;;
esac
touch "$OUT/.done-$PHASE"
