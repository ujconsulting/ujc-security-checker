#!/usr/bin/env python3
"""Ledgers of the checker: decisions per reviewed tool, review runs, findings (metadata only).

The ledgers are local data and live in the git-ignored folder private/ledger/ (its own private
git repository; override with UJC_LEDGER_DIR). This file is the generic tool; it holds no data.

    reviews.jsonl             one line per record: kind, decision, decided_at, usage
    runs.jsonl                one line per review run (append-only)
    findings/<record>.jsonl   one line per finding - metadata only, NO free text

What a record's README already says (upstream, fork, latest verdict) is NOT copied here: the
exporter reads it from the README table, so there is one source per fact.

    python tools/ledger.py review set <record> [--kind K] [--decision D] [--decided-at YYYY-MM-DD]
                                      [--usage a,b]
    python tools/ledger.py run add --record R --round N --step S --reviewer claude|codex|human
                                   --started ISO [--ended ISO] [--model M] [--effort E]
                                   [--verdict V] [--commit SHA] [--thread-id T]
    python tools/ledger.py run codex --record R --round N --step S [--commit SHA] -- <codex_ro.py args>
        Runs tools/codex_ro.py unchanged (output passes through), then records the run with model,
        effort, start, end and the THREAD_ID the wrapper prints. The verdict is read from the
        last line of --out-file if it is a known verdict line. Exit code = that of the wrapper.
    python tools/ledger.py run backfill [--dry-run]
        Adds the runs of all review rounds that are not in runs.jsonl yet, read from the header
        table of private/records/<record>/reviews/round-NN-*.md (Kind, Reviewer, Audited state, Verdict).
    python tools/ledger.py finding add --record R --id rNN-X --severity S --category C
                                       --status ST [--location path:line] [--disclosure-id ID]
                                       [--confidential] [--source FILE]
    python tools/ledger.py finding set <record> <finding_id> [--status ST] [--severity S]
                                       [--category C] [--location L] [--disclosure-id ID]
    python tools/ledger.py check
    python tools/ledger.py salt          creates the private salt of the export placeholders once
    python tools/ledger.py --self-test

Exit 0 ok, 1 ledger invalid, 2 operator error. Output ASCII only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("UJC_CHECKER_ROOT") or Path(__file__).resolve().parents[1])

KINDS = ("repo", "plugin", "skill", "mcp", "cli", "pip", "npm")
VERDICTS = ("approved", "approved-with-conditions", "not-approved", "do-not-use", "pending")
DECISIONS = ("adopt", "adopt-fork", "trial", "reject", "on-hold", "pending", "retired")
USAGE = ("dev-tooling", "agent-orchestration", "code-review", "knowledge-rag", "docs-conversion",
         "erp", "web", "automation", "security", "none")
REVIEWERS = ("claude", "codex", "human")
STEPS = ("intake", "supply-chain", "scan", "audit", "final-test", "container-test", "patch-round",
         "upstream-research", "recheck", "behavior-probe", "usage-analysis")
SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = ("injection", "path-traversal", "unsafe-exec", "authn-authz", "secrets", "data-leak",
              "network-exposure", "sandbox-escape", "supply-chain", "dos", "config", "docs", "other")
FINDING_STATUS = ("open", "fixed-fork", "fixed-upstream", "accepted-risk", "not-confirmed",
                  "duplicate")

RECORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FINDING_ID_RE = re.compile(r"^r\d{2}-[A-Za-z0-9._-]{1,28}$")
DISCLOSURE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
THREAD_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,64}$")
# a location is a path relative to the reviewed project's root: no drive letter, no leading
# slash or backslash, no '..', no home directory, no quarantine or session folders
_LOC_BAD = re.compile(r"(^[A-Za-z]:)|(^[/\\~])|(\\)|(^|/)\.\.(/|$)|(^|/)(quarantine|private|\.claudex-tmp)/"
                      r"|(^|/)(users|home)/", re.I)
LOCATION_RE = re.compile(r"^[A-Za-z0-9._@+/-]{1,180}(:\d{1,6}(-\d{1,6})?)?$")

REVIEW_KEYS = {"record", "kind", "decision", "decided_at", "usage"}
RUN_KEYS = {"record", "round", "step", "reviewer", "model", "effort", "started_at", "ended_at",
            "verdict", "commit", "thread_id", "source"}
FINDING_KEYS = {"record", "finding_id", "round", "severity", "severity_guessed", "category",
                "status", "location", "disclosure_id", "duplicate_of", "confidential", "source"}


class LedgerError(Exception):
    """Something the operator has to fix (exit 2)."""


def out(text: str = "") -> None:
    sys.stdout.write(str(text).encode("ascii", "replace").decode("ascii") + "\n")
    sys.stdout.flush()


def err(text: str) -> None:
    sys.stderr.write(str(text).encode("ascii", "replace").decode("ascii") + "\n")
    sys.stderr.flush()


def ledger_dir() -> Path:
    return Path(os.environ.get("UJC_LEDGER_DIR") or ROOT / "private" / "ledger")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value):
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else None


def _date_ok(value) -> bool:
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", str(value or ""))) and parse_iso(f"{value}T00:00:00Z") is not None


def location_ok(value) -> bool:
    return isinstance(value, str) and bool(LOCATION_RE.match(value)) and not _LOC_BAD.search(value)


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #

def read_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise LedgerError(f"{path.name}: has a BOM")
    for nr, line in enumerate(raw.decode("utf-8").split("\n"), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise LedgerError(f"{path.name} line {nr}: not JSON ({exc})") from exc
        if not isinstance(row, dict):
            raise LedgerError(f"{path.name} line {nr}: not an object")
        rows.append(row)
    return rows


def write_jsonl(path: Path, rows) -> None:
    """LF, no BOM, ASCII (escaped), via a sibling file and os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="ascii", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True, sort_keys=False) + "\n")
    os.replace(tmp, path)


def reviews_file() -> Path:
    return ledger_dir() / "reviews.jsonl"


def runs_file() -> Path:
    return ledger_dir() / "runs.jsonl"


def findings_file(record: str) -> Path:
    return ledger_dir() / "findings" / f"{check_record(record)}.jsonl"


def check_record(record: str) -> str:
    if not RECORD_RE.match(record or ""):
        raise LedgerError(f"invalid record name {record!r}")
    return record


def load_reviews():
    return read_jsonl(reviews_file())


def load_runs():
    return read_jsonl(runs_file())


def load_findings():
    rows = []
    d = ledger_dir() / "findings"
    if d.is_dir():
        for f in sorted(d.glob("*.jsonl")):
            rows += read_jsonl(f)
    return rows


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def _enum(errors, who, key, value, allowed, optional=False):
    if value is None and optional:
        return
    if value not in allowed:
        errors.append(f"{who}: {key} {value!r} not in {'/'.join(allowed)}")


def check_review(r) -> list:
    errors, who = [], f"review {r.get('record')}"
    extra = set(r) - REVIEW_KEYS
    if extra:
        errors.append(f"{who}: unknown fields {sorted(extra)}")
    if not RECORD_RE.match(str(r.get("record") or "")):
        errors.append(f"{who}: record invalid")
    _enum(errors, who, "kind", r.get("kind"), KINDS)
    _enum(errors, who, "decision", r.get("decision"), DECISIONS, optional=True)
    if r.get("decided_at") is not None and not _date_ok(r["decided_at"]):
        errors.append(f"{who}: decided_at must be YYYY-MM-DD")
    usage = r.get("usage")
    if usage is not None:
        parts = str(usage).split(",")
        if len(str(usage)) > 64 or any(p not in USAGE for p in parts) or len(set(parts)) != len(parts):
            errors.append(f"{who}: usage {usage!r} - comma list of {'/'.join(USAGE)}, max 64 chars")
    return errors


def check_run(r) -> list:
    errors, who = [], f"run {r.get('record')} r{r.get('round')} {r.get('step')}"
    extra = set(r) - RUN_KEYS
    if extra:
        errors.append(f"{who}: unknown fields {sorted(extra)}")
    if not RECORD_RE.match(str(r.get("record") or "")):
        errors.append(f"{who}: record invalid")
    if not isinstance(r.get("round"), int) or isinstance(r.get("round"), bool) or r["round"] < 0:
        errors.append(f"{who}: round must be an integer >= 0 (0 = outside a round)")
    _enum(errors, who, "step", r.get("step"), STEPS)
    _enum(errors, who, "reviewer", r.get("reviewer"), REVIEWERS)
    _enum(errors, who, "verdict", r.get("verdict"), VERDICTS, optional=True)
    if r.get("model") is not None and not MODEL_RE.match(str(r["model"])):
        errors.append(f"{who}: model invalid")
    if r.get("effort") is not None and not re.match(r"^[a-z]{1,16}$", str(r["effort"])):
        errors.append(f"{who}: effort invalid")
    if parse_iso(r.get("started_at")) is None:
        errors.append(f"{who}: started_at must be ISO 8601 with zone")
    if r.get("ended_at") is not None and parse_iso(r["ended_at"]) is None:
        errors.append(f"{who}: ended_at must be ISO 8601 with zone or null")
    if r.get("commit") is not None and not COMMIT_RE.match(str(r["commit"])):
        errors.append(f"{who}: commit must be a hex SHA")
    if r.get("thread_id") is not None and not THREAD_RE.match(str(r["thread_id"])):
        errors.append(f"{who}: thread_id invalid")
    return errors


def check_finding(r) -> list:
    errors, who = [], f"finding {r.get('record')}/{r.get('finding_id')}"
    extra = set(r) - FINDING_KEYS
    if extra:
        errors.append(f"{who}: unknown fields {sorted(extra)} (metadata only, no free text)")
    if not RECORD_RE.match(str(r.get("record") or "")):
        errors.append(f"{who}: record invalid")
    fid = str(r.get("finding_id") or "")
    if not FINDING_ID_RE.match(fid):
        errors.append(f"{who}: finding_id must be r<NN>-<local id> (max 32)")
    elif int(fid[1:3]) != r.get("round"):
        errors.append(f"{who}: round does not match the finding_id")
    _enum(errors, who, "severity", r.get("severity"), SEVERITIES)
    _enum(errors, who, "category", r.get("category"), CATEGORIES)
    _enum(errors, who, "status", r.get("status"), FINDING_STATUS)
    if r.get("location") is not None and not location_ok(r["location"]):
        errors.append(f"{who}: location must be a path relative to the reviewed project")
    if r.get("disclosure_id") is not None and not DISCLOSURE_ID_RE.match(str(r["disclosure_id"])):
        errors.append(f"{who}: disclosure_id invalid")
    if (r.get("status") == "duplicate") != bool(r.get("duplicate_of")):
        errors.append(f"{who}: duplicate_of is required exactly for status duplicate")
    for k in ("severity_guessed", "confidential"):
        if k in r and not isinstance(r[k], bool):
            errors.append(f"{who}: {k} must be true or false")
    src = r.get("source")
    if src is not None and (not isinstance(src, str) or not LOCATION_RE.match(src)
                            or re.search(r"^[A-Za-z]:|^[/\\~]|\\|(^|/)\.\.(/|$)", src)):
        errors.append(f"{who}: source must be a repo-relative path")
    return errors


def check_all():
    errors = []
    seen = set()
    for r in load_reviews():
        errors += check_review(r)
        if r.get("record") in seen:
            errors.append(f"review {r.get('record')}: duplicate line")
        seen.add(r.get("record"))
    runs = load_runs()
    keys = set()
    for r in runs:
        errors += check_run(r)
        k = (r.get("record"), r.get("round"), r.get("step"), r.get("started_at"))
        if k in keys:
            errors.append(f"run {k}: duplicate key (record, round, step, started_at)")
        keys.add(k)
    findings = load_findings()
    ids = {}
    for f in findings:
        errors += check_finding(f)
        k = (f.get("record"), f.get("finding_id"))
        if k in ids:
            errors.append(f"finding {k}: duplicate")
        ids[k] = f
    for (record, _fid), f in ids.items():
        if f.get("duplicate_of") and (record, f["duplicate_of"]) not in ids:
            errors.append(f"finding {record}/{_fid}: duplicate_of {f['duplicate_of']} not in the ledger")
    d = ledger_dir() / "findings"
    if d.is_dir():
        for p in d.glob("*.jsonl"):
            if any(row.get("record") != p.stem for row in read_jsonl(p)):
                errors.append(f"findings/{p.name}: holds lines of another record")
    return errors, {"reviews": len(seen), "runs": len(runs), "findings": len(findings)}


# --------------------------------------------------------------------------- #
# Verdicts from the records (README table, round files)
# --------------------------------------------------------------------------- #

def map_verdict(text):
    """Maps a verdict line of a round or README ('FINAL TEST: NOT APPROVED', 'VERDICT: DO NOT
    USE', 'VERDICT: USABLE WITH CONDITIONS' ...) to the fixed list; None if none recognised."""
    t = " ".join(str(text or "").upper().replace("_", " ").split())
    if not t:
        return None
    if "DO NOT USE" in t or "NOT USABLE" in t:
        return "do-not-use"
    if "NOT APPROVED" in t:
        return "not-approved"
    if "WITH CONDITIONS" in t or "WITH RESERVATIONS" in t:
        return "approved-with-conditions"
    if re.search(r"\b(APPROVED|USABLE)\b", t):
        return "approved"
    return None


def step_of(kind: str):
    k = kind.lower()
    for key, step in (("upstream research", "upstream-research"), ("initial audit", "audit"),
                      ("recheck", "recheck"), ("final test", "final-test"),
                      ("container test", "container-test"), ("behavior probe", "behavior-probe"),
                      ("supply chain", "supply-chain"), ("scan", "scan"), ("intake", "intake"),
                      ("usage analysis", "usage-analysis"), ("patch", "patch-round")):
        if key in k:
            return step
    return None


_HEAD_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|\s*$", re.M)


def round_header(path: Path) -> dict:
    """The header table and title date of a round file as {key: value}."""
    text = path.read_text(encoding="utf-8", errors="replace")
    head = {}
    title = text.splitlines()[0] if text else ""
    m = re.search(r"\([^)]*?(\d{2})\.(\d{2})\.(\d{4})\)", title)
    if m:
        head["date"] = f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
    for key, value in _HEAD_ROW.findall(text.split("\n## ", 1)[0]):
        if key.strip() and set(key.strip()) != {"-"}:
            head.setdefault(key.strip().lower(), value)
    return head


def run_from_round(record: str, path: Path):
    """A run line from a round file, or None if the file has no usable header."""
    m = re.match(r"^round-(\d{2})-", path.name)
    head = round_header(path)
    step = step_of(head.get("kind", "")) or step_of(path.stem.replace("-", " "))
    if not m or not step or "date" not in head:
        return None
    rev_text = head.get("reviewer", "")
    mm = re.search(r"`(gpt-[A-Za-z0-9.-]+)`(?:/`?([a-z]+)`?)?", rev_text)
    # the reviewer is the one the row starts with ("Claude (in parallel with Codex)" is Claude);
    # a row that names nobody counts as the agent session that wrote the round (claude)
    if mm or re.match(r"\s*codex\b", rev_text, re.I):
        reviewer = "codex"
    elif re.match(r"\s*(owner|human)\b", rev_text, re.I):
        reviewer = "human"
    else:
        reviewer = "claude"
    model = effort = None
    if mm:
        model, effort = mm.group(1), mm.group(2)
    elif reviewer == "claude":
        sub = re.search(r"\b(opus|sonnet|haiku)\b", rev_text, re.I)
        model = f"claude-{sub.group(1).lower()}-subagent" if sub and "main model" not in rev_text.lower() else None
    commit = None
    cm = re.search(r"`([0-9a-f]{7,40})`", head.get("audited state", ""))
    if cm:
        commit = cm.group(1)
    # only a literal verdict line in backticks counts, never prose ("in substance usable ...")
    vm = re.search(r"`((?:VERDICT|FINAL TEST)\s*:[^`]*)`|`(DO NOT USE)`", head.get("verdict", ""))
    verdict = map_verdict(vm.group(1) or vm.group(2)) if vm else None
    return {"record": record, "round": int(m.group(1)), "step": step, "reviewer": reviewer,
            "model": model, "effort": effort, "started_at": f"{head['date']}T00:00:00Z",
            "ended_at": None, "verdict": verdict, "commit": commit, "thread_id": None,
            "source": path.relative_to(ROOT).as_posix() if _within(path, ROOT) else path.name}


def _within(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_review_set(a) -> int:
    record = check_record(a.record)
    rows = load_reviews()
    row = next((r for r in rows if r.get("record") == record), None)
    if row is None:
        row = {"record": record, "kind": None, "decision": None, "decided_at": None, "usage": None}
        rows.append(row)
    for key, value in (("kind", a.kind), ("decision", a.decision), ("decided_at", a.decided_at),
                       ("usage", a.usage)):
        if value is not None:
            row[key] = value or None
    errors = check_review(row)
    if errors:
        raise LedgerError("; ".join(errors))
    write_jsonl(reviews_file(), sorted(rows, key=lambda r: r["record"]))
    out(f"OK: review {record} saved")
    return 0


def add_run(row) -> None:
    errors = check_run(row)
    if errors:
        raise LedgerError("; ".join(errors))
    rows = load_runs()
    key = (row["record"], row["round"], row["step"], row["started_at"])
    if any((r.get("record"), r.get("round"), r.get("step"), r.get("started_at")) == key for r in rows):
        raise LedgerError(f"run {key} is already in the ledger")
    rows.append(row)
    write_jsonl(runs_file(), rows)


def cmd_run_add(a) -> int:
    row = {"record": check_record(a.record), "round": a.round, "step": a.step, "reviewer": a.reviewer,
           "model": a.model, "effort": a.effort, "started_at": a.started, "ended_at": a.ended,
           "verdict": a.verdict, "commit": a.commit, "thread_id": a.thread_id}
    add_run(row)
    out(f"OK: run {row['record']} r{row['round']} {row['step']} recorded")
    return 0


def _opt(args, name):
    """Value of --name / --name=value in a wrapper argument list."""
    for i, x in enumerate(args):
        if x == name and i + 1 < len(args):
            return args[i + 1]
        if x.startswith(name + "="):
            return x[len(name) + 1:]
    return None


def cmd_run_codex(a) -> int:
    check_record(a.record)
    if a.step not in STEPS:
        raise LedgerError(f"step {a.step!r} not in {'/'.join(STEPS)}")
    args = list(a.wrapper_args)
    if args and args[0] == "--":
        args = args[1:]
    started = now_iso()
    proc = subprocess.run([sys.executable, str(ROOT / "tools" / "codex_ro.py"), *args],
                          stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    sys.stdout.write(proc.stdout.encode("ascii", "replace").decode("ascii"))
    sys.stdout.flush()
    ended = now_iso()
    thread = None
    for line in proc.stdout.splitlines():
        if line.startswith("THREAD_ID="):
            thread = line[len("THREAD_ID="):].strip()
    model, effort = _opt(args, "--model"), _opt(args, "--effort")
    if model is None or effort is None:
        src = (ROOT / "tools" / "codex_ro.py").read_text(encoding="utf-8", errors="replace")
        dm = re.search(r'^DEFAULT_MODEL = "([^"]+)"', src, re.M)
        de = re.search(r'^DEFAULT_EFFORT = "([^"]+)"', src, re.M)
        model = model or (dm.group(1) if dm else None)
        effort = effort or (de.group(1) if de else None)
    verdict = None
    out_file = _opt(args, "--out-file")
    if out_file and Path(out_file).is_file():
        lines = [x for x in Path(out_file).read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
        if lines and re.match(r"^\W*(VERDICT|FINAL TEST)\s*:", lines[-1], re.I):
            verdict = map_verdict(lines[-1])
    if proc.returncode != 0:
        err(f"NOTE: codex_ro.py exit {proc.returncode} - run recorded without verdict")
        verdict = None
    row = {"record": a.record, "round": a.round, "step": a.step, "reviewer": "codex",
           "model": model, "effort": effort, "started_at": started, "ended_at": ended,
           "verdict": verdict, "commit": a.commit,
           "thread_id": thread if thread and THREAD_RE.match(thread) else None}
    add_run(row)
    out(f"OK: run {a.record} r{a.round} {a.step} recorded (thread {row['thread_id'] or '-'})")
    return proc.returncode


def round_files(root: Path) -> list:
    """Review rounds of the upstream review and of an own version, in a fixed order."""
    private = root / "private"
    return sorted(list((private / "records").glob("*/reviews/round-*.md"))
                  + list((private / "repos").glob("*/reviews/round-*.md")))


def cmd_run_backfill(a) -> int:
    rows = load_runs()
    have = {(r.get("record"), r.get("round"), r.get("step")) for r in rows}
    added, skipped = [], []
    for path in round_files(ROOT):
        record = path.parent.parent.name
        row = run_from_round(record, path)
        if row is None:
            skipped.append(path.relative_to(ROOT).as_posix())
            continue
        if (record, row["round"], row["step"]) in have:
            continue
        errors = check_run(row)
        if errors:
            skipped.append(f"{path.relative_to(ROOT).as_posix()}: {'; '.join(errors)}")
            continue
        added.append(row)
        have.add((record, row["round"], row["step"]))
    for row in added:
        out(f"  {row['record']} r{row['round']:02d} {row['step']} {row['reviewer']} "
            f"{row['model'] or '-'} {row['verdict'] or '-'}")
    for s in skipped:
        out(f"  SKIPPED: {s}")
    if not a.dry_run and added:
        write_jsonl(runs_file(), rows + added)
    out(f"{'DRY RUN: ' if a.dry_run else 'OK: '}{len(added)} runs added, {len(skipped)} skipped")
    return 0


def cmd_finding_add(a) -> int:
    record = check_record(a.record)
    m = FINDING_ID_RE.match(a.id or "")
    row = {"record": record, "finding_id": a.id, "round": int(a.id[1:3]) if m else -1,
           "severity": a.severity, "category": a.category, "status": a.status,
           "location": a.location, "disclosure_id": a.disclosure_id}
    if a.duplicate_of:
        row["duplicate_of"] = a.duplicate_of
    if a.confidential:
        row["confidential"] = True
    if a.source:
        row["source"] = a.source
    errors = check_finding(row)
    if errors:
        raise LedgerError("; ".join(errors))
    rows = read_jsonl(findings_file(record))
    if any(r.get("finding_id") == a.id for r in rows):
        raise LedgerError(f"{record}/{a.id} is already in the ledger")
    write_jsonl(findings_file(record), rows + [row])
    out(f"OK: finding {record}/{a.id} recorded")
    return 0


def cmd_finding_set(a) -> int:
    record = check_record(a.record)
    rows = read_jsonl(findings_file(record))
    row = next((r for r in rows if r.get("finding_id") == a.finding_id), None)
    if row is None:
        raise LedgerError(f"{record}/{a.finding_id} not in the ledger")
    for key in ("status", "severity", "category", "location", "disclosure_id", "duplicate_of"):
        value = getattr(a, key)
        if value is not None:
            row[key] = value or None
    if row.get("duplicate_of") is None:
        row.pop("duplicate_of", None)
    errors = check_finding(row)
    if errors:
        raise LedgerError("; ".join(errors))
    write_jsonl(findings_file(record), rows)
    out(f"OK: finding {record}/{a.finding_id} updated")
    return 0


def cmd_salt(_a) -> int:
    """Creates the private salt for the export placeholders once; never replaces it (a new
    salt changes every placeholder in the dashboard)."""
    path = ledger_dir() / "salt"
    if path.exists():
        out("OK: salt exists (left unchanged)")
        return 0
    import secrets
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", encoding="ascii", newline="\n") as fh:
        fh.write(secrets.token_hex(32) + "\n")
    out("OK: salt created")
    return 0


def cmd_check(_a) -> int:
    errors, counts = check_all()
    for e in errors:
        out(f"ERROR: {e}")
    out(f"ledger: {counts['reviews']} reviews, {counts['runs']} runs, {counts['findings']} findings, "
        f"{len(errors)} errors")
    return 1 if errors else 0


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def self_test() -> int:
    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    check("verdict final test", map_verdict("`FINAL TEST: NOT APPROVED` (1 HIGH)") == "not-approved")
    check("verdict do not use", map_verdict("VERDICT: DO NOT USE") == "do-not-use")
    check("verdict conditions", map_verdict("VERDICT: USABLE WITH CONDITIONS") == "approved-with-conditions")
    check("verdict approved", map_verdict("FINAL TEST: APPROVED") == "approved")
    check("verdict none", map_verdict("no upstream fix") is None)
    check("location relative", location_ok("src/a/b.py:12-30"))
    # public-check: begin-allow internal  (invented paths the location check must refuse)
    for bad in ("C:/x/y.py", "/home/u/x", "~/x", "a/../b", "quarantine/x/y", "x\\y", "Users/me/x",
                "private/x", "a b.py"):
        # public-check: end-allow
        check(f"location refused {bad}", not location_ok(bad))
    good = {"record": "tool", "finding_id": "r04-R7", "round": 4, "severity": "high",
            "category": "injection", "status": "open", "location": "src/x.py:3", "disclosure_id": None}
    check("finding ok", check_finding(good) == [])
    check("finding free text refused", check_finding({**good, "title": "x"}) != [])
    check("finding round mismatch", check_finding({**good, "round": 5}) != [])
    check("finding duplicate without target", check_finding({**good, "status": "duplicate"}) != [])
    check("finding bad category", check_finding({**good, "category": "rce"}) != [])
    run = {"record": "tool", "round": 0, "step": "scan", "reviewer": "human", "model": None,
           "effort": None, "started_at": "2026-10-12T00:00:00Z", "ended_at": None, "verdict": None,
           "commit": None, "thread_id": None}
    check("run ok", check_run(run) == [])
    check("run without zone refused", check_run({**run, "started_at": "2026-10-12T00:00:00"}) != [])
    check("run bad step", check_run({**run, "step": "lunch"}) != [])
    check("review usage list", check_review({"record": "t", "kind": "pip", "decision": "trial",
                                            "decided_at": "2026-10-12", "usage": "erp,web"}) == [])
    check("review usage unknown", check_review({"record": "t", "kind": "pip", "usage": "my-project"}) != [])
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        rf = root / "private" / "records" / "tool" / "reviews" / "round-04-final-test.md"
        rf.parent.mkdir(parents=True)
        rf.write_text("# Round 04 \u2014 final test (05.10.2026)\n\n| | |\n|---|---|\n"
                      "| Kind | final test |\n| Audited state | `a62dbbd` (`1.0+ujc.1`) |\n"
                      "| Reviewer | Codex `gpt-6-astra`/medium (read-only) |\n"
                      "| Verdict | `FINAL TEST: NOT APPROVED` |\n\n## Brief\n| Verdict | approved |\n",
                      encoding="utf-8")
        own = root / "private" / "repos" / "tool" / "reviews" / "round-05-recheck.md"
        own.parent.mkdir(parents=True)
        own.write_text("# Round 05\n", encoding="utf-8")
        check("backfill sees both review locations", round_files(root) == sorted([rf, own]))
        r = run_from_round("tool", rf)
        check("round header parsed", r is not None and r["step"] == "final-test" and r["reviewer"] == "codex"
              and r["model"] == "gpt-6-astra" and r["effort"] == "medium" and r["commit"] == "a62dbbd"
              and r["verdict"] == "not-approved" and r["started_at"] == "2026-10-05T00:00:00Z")
        old = os.environ.get("UJC_LEDGER_DIR")
        os.environ["UJC_LEDGER_DIR"] = str(root / "ledger")
        try:
            write_jsonl(findings_file("tool"), [good])
            raw = findings_file("tool").read_bytes()
            check("jsonl LF no BOM ascii", b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf"))
            check("ledger check clean", check_all()[0] == [])
            write_jsonl(findings_file("tool"), [good, good])
            check("duplicate finding found", any("duplicate" in e for e in check_all()[0]))
        finally:
            if old is None:
                os.environ.pop("UJC_LEDGER_DIR", None)
            else:
                os.environ["UJC_LEDGER_DIR"] = old
    out(f"ledger self-test: {ok}/{total} {'OK' if ok == total else 'FAILED'}")
    return 0 if ok == total else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ledgers of the checker (decisions, runs, findings)")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="area")
    rv = sub.add_parser("review").add_subparsers(dest="cmd")
    rs = rv.add_parser("set")
    rs.add_argument("record")
    rs.add_argument("--kind", choices=KINDS)
    rs.add_argument("--decision", choices=DECISIONS + ("",))
    rs.add_argument("--decided-at", dest="decided_at")
    rs.add_argument("--usage")
    ru = sub.add_parser("run").add_subparsers(dest="cmd")
    ra = ru.add_parser("add")
    ra.add_argument("--record", required=True)
    ra.add_argument("--round", type=int, required=True)
    ra.add_argument("--step", required=True, choices=STEPS)
    ra.add_argument("--reviewer", required=True, choices=REVIEWERS)
    ra.add_argument("--started", required=True)
    for k in ("ended", "model", "effort", "commit"):
        ra.add_argument(f"--{k}")
    ra.add_argument("--verdict", choices=VERDICTS)
    ra.add_argument("--thread-id", dest="thread_id")
    rc = ru.add_parser("codex")
    rc.add_argument("--record", required=True)
    rc.add_argument("--round", type=int, required=True)
    rc.add_argument("--step", required=True, choices=STEPS)
    rc.add_argument("--commit")
    rc.add_argument("wrapper_args", nargs=argparse.REMAINDER)
    rb = ru.add_parser("backfill")
    rb.add_argument("--dry-run", action="store_true")
    fi = sub.add_parser("finding").add_subparsers(dest="cmd")
    fa = fi.add_parser("add")
    fa.add_argument("--record", required=True)
    fa.add_argument("--id", required=True)
    fa.add_argument("--severity", required=True, choices=SEVERITIES)
    fa.add_argument("--category", required=True, choices=CATEGORIES)
    fa.add_argument("--status", required=True, choices=FINDING_STATUS)
    for k in ("location", "disclosure-id", "duplicate-of", "source"):
        fa.add_argument(f"--{k}", dest=k.replace("-", "_"))
    fa.add_argument("--confidential", action="store_true")
    fs = fi.add_parser("set")
    fs.add_argument("record")
    fs.add_argument("finding_id")
    fs.add_argument("--status", choices=FINDING_STATUS)
    fs.add_argument("--severity", choices=SEVERITIES)
    fs.add_argument("--category", choices=CATEGORIES)
    for k in ("location", "disclosure-id", "duplicate-of"):
        fs.add_argument(f"--{k}", dest=k.replace("-", "_"))
    sub.add_parser("check")
    sub.add_parser("salt")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    handlers = {("review", "set"): cmd_review_set, ("run", "add"): cmd_run_add,
                ("run", "codex"): cmd_run_codex, ("run", "backfill"): cmd_run_backfill,
                ("finding", "add"): cmd_finding_add, ("finding", "set"): cmd_finding_set,
                ("check", None): cmd_check, ("salt", None): cmd_salt}
    handler = handlers.get((a.area, getattr(a, "cmd", None)))
    if handler is None:
        ap.error("give a command (review set, run add|codex|backfill, finding add|set, check) or --self-test")
    try:
        return handler(a)
    except LedgerError as exc:
        err(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
