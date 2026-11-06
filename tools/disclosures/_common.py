"""Shared building blocks of the disclosure tools (tools/disclosures/).

Python standard library and the gh CLI only. No assumptions about a particular
agent: every tool is a plain command line.

Contents:
- paths (register, configuration, reports, approvals)
- writing JSON/text with LF and without BOM
- gh calls READ-ONLY (gh_get / gh_get_list) and the ONE writing path gh_post,
  used only by the submit tools after a valid approval
- draft format (JSON block "disclosure" + text after the marker)
- hash-bound one-time approvals
- ASCII output on the console
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

ROOT = Path(os.environ.get("UJC_CHECKER_ROOT") or Path(__file__).resolve().parents[2])

# Public part (the repository is public): publicly visible disclosures only.
DISCLOSURES = ROOT / "disclosures"
REGISTER = DISCLOSURES / "register.json"
REGISTER_README = DISCLOSURES / "README.md"
WATCH_CONFIG = DISCLOSURES / "watch_config.json"
REPOS = ROOT / "repos"

# Confidential part (git-ignored): embargoed drafts, confidential disclosures,
# approvals, mailbox state, reports with confidential content, local configuration.
PRIVATE = ROOT / "private"
PRIVATE_DISCLOSURES = PRIVATE / "disclosures"
REGISTER_PRIVATE = PRIVATE_DISCLOSURES / "register.json"
REGISTER_README_PRIVATE = PRIVATE_DISCLOSURES / "README.md"
REPORTS_PRIVATE = PRIVATE_DISCLOSURES / "reports"
# reports without confidential content (formerly disclosures/reports/): local only, never versioned
REPORTS = PRIVATE_DISCLOSURES / "public-reports"
APPROVALS = PRIVATE_DISCLOSURES / "approvals"
CHECKS = PRIVATE_DISCLOSURES / "checks"
ENV_FILE = ROOT / ".env"
NEW_FLAG = PRIVATE_DISCLOSURES / "NEW.flag"
MAIL_STATUS = PRIVATE_DISCLOSURES / "mail_status.json"
SEEN = PRIVATE_DISCLOSURES / "seen.json"
REACTIONS_LOG = PRIVATE_DISCLOSURES / "reactions.jsonl"
WATCH_CONFIG_LOCAL = PRIVATE_DISCLOSURES / "watch_config.local.json"
LEAK_NAMES = PRIVATE_DISCLOSURES / "leak_names.txt"
# shared deny list of internal names, also read by tools/public_check.py
DENYLIST = PRIVATE / "public_check_denylist.txt"
PRIVATE_REPOS = PRIVATE / "repos"
# former "public" layer of a record (since 06.11.2026 nothing below repos/<name>/ but the
# summary README is versioned): register, REGISTER.md, reports, policy evidence, reviews
PRIVATE_RECORDS = PRIVATE / "records"

# --------------------------------------------------------------------------- #
# Storage per reviewed repository ("record", rule since 12.10.2026)
# --------------------------------------------------------------------------- #
# disclosures/ and private/disclosures/ in the root hold ONLY what belongs to the checker
# itself (inbox of the own repository, own_repos.md, watch_config*, its own findings).
# Everything about a reviewed repository lives in that repository's folders:
#     private/records/<record>/disclosures/  former public part (now local too): register.json,
#                                          REGISTER.md/_de.md, reports/, policy/
#     (repos/<record>/ holds only the summary README.md / README_de.md and is versioned)
#     private/repos/<record>/disclosures/  confidential part: register.json, REGISTER.md,
#                                          approvals/, checks/, reports/, reply-drafts/
# Every location is derived at RUN TIME from the current REGISTER / REGISTER_PRIVATE: a
# self-test that points the register into a temporary folder therefore also keeps the
# overviews, approvals and checks there (it never touches the real tree). Without the usual
# layout (register file not inside a folder named "disclosures") records are switched off
# and everything stays in the given files.

RECORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
UPSTREAM_ROW = re.compile(r"^\|\s*Upstream\s*\|\s*`((?:[a-z][a-z0-9_]*:)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)`", re.M)


def _base(register_file: Path):
    """Store root (checker root resp. private/) for a register file at <base>/disclosures/register.json."""
    return register_file.parent.parent if register_file.parent.name == "disclosures" else None


def records_enabled() -> bool:
    return _base(REGISTER) is not None and _base(REGISTER_PRIVATE) is not None


def check_record(record: str) -> str:
    if not RECORD_RE.match(record or ""):
        raise DisclosureError(f"invalid record name {record!r} (folder name below repos/)")
    return record


def record_dirs(record: str = ""):
    """(public dir, confidential dir) of a record; '' = the checker itself (root folders)."""
    if not record or not records_enabled():
        return REGISTER.parent, REGISTER_PRIVATE.parent
    check_record(record)
    return (_base(REGISTER_PRIVATE) / "records" / record / "disclosures",
            _base(REGISTER_PRIVATE) / "repos" / record / "disclosures")


def upstream_records() -> dict:
    """{upstream key ('owner/name' or 'alias:owner/name'): record} from repos/*/README.md."""
    res = {}
    base = _base(REGISTER)
    if base is None:
        return res
    for readme in sorted((base / "repos").glob("*/README.md")):
        try:
            m = UPSTREAM_ROW.search(readme.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if m:
            res.setdefault(m.group(1), readme.parent.name)
    return res


def _record_from_path(path) -> str:
    if not path:
        return ""
    p = Path(path)
    for base in (_base(REGISTER), _base(REGISTER_PRIVATE), ROOT, PRIVATE):
        if base is None:
            continue
        try:
            parts = (p if p.is_absolute() else ROOT / p).resolve().relative_to(Path(base).resolve()).parts
        except (ValueError, OSError):
            continue
        if len(parts) >= 3 and parts[0] in ("repos", "records") and RECORD_RE.match(parts[1]):
            return parts[1]
        if len(parts) >= 4 and parts[:2] == ("private", "records") and RECORD_RE.match(parts[2]):
            return parts[2]
        if len(parts) >= 4 and parts[:2] == ("private", "repos") and RECORD_RE.match(parts[2]):
            return parts[2]
    return ""


def record_of(meta, draft=None) -> str:
    """Record of a draft or register entry: field 'record', else the folder the draft lies in
    (repos/<record>/..., private/records/<record>/... or private/repos/<record>/...), else the record whose README names the
    repository as 'Upstream'. '' = the checker itself (or records switched off)."""
    if not records_enabled():
        return ""
    if meta.get("record"):
        return check_record(meta["record"])
    for path in (draft, meta.get("draft")):
        r = _record_from_path(path)
        if r:
            return r
    key = meta.get("repo") or ""
    if meta.get("forge") not in (None, "", "github"):
        key = f"{meta['forge']}:{key}"
    return upstream_records().get(key, "")


def register_files():
    """Every register file that exists: root parts and all records (public and confidential)."""
    files = [REGISTER, REGISTER_PRIVATE]
    if records_enabled():
        files += sorted((_base(REGISTER_PRIVATE) / "records").glob("*/disclosures/register.json"))
        files += sorted((_base(REGISTER_PRIVATE) / "repos").glob("*/disclosures/register.json"))
    return files


STATUS_VALUES = ("open", "answered", "fix-pr", "fixed", "rejected", "closed")
CHANNELS = ("issue", "advisory", "email", "comment")
SEVERITY_CLASSES = ("critical", "non-critical")
# optional register fields (since 12.10.2026, for the dashboard export); the lists match
# tools/ledger.py (SEVERITIES, CATEGORIES) - export_dashboard.py --self-test checks that
SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = ("injection", "path-traversal", "unsafe-exec", "authn-authz", "secrets", "data-leak",
              "network-exposure", "sandbox-escape", "supply-chain", "dos", "config", "docs", "other")
DATE_FIELDS = ("due_by", "embargo_until", "published_at", "answered_at", "fixed_at", "closed_at",
               "verified_at")
# How upstream dealt with a disclosure (filled by the watch from issue state, timeline and linked
# PRs/commits - upstream's own account, a claim until "verification" says otherwise):
#   upstream_state  issue: open | closed; advisory: triage | draft | published | closed | withdrawn
#   resolution      fix-merged-pr (a linked PR was merged) | fix-commit (closed with a referenced
#                   commit, no merged PR) | pr-open (open, a linked PR exists) | wontfix
#                   (not_planned) | duplicate | closed-no-fix-ref (closed without PR/commit) |
#                   advisory-published | advisory-closed
#   fix_commit      SHA of the fix (merged PR's merge commit, else the referenced commit)
#   fix_release     first release tag that contains fix_commit
#   closed_via_bot  the closing comment carries a bot signature
# and what WE found when reading the fixed code (set by a human with "register.py set"):
#   verification    verified-fixed | partial | not-fixed | unverified ; verified_at its date
UPSTREAM_STATES = ("open", "closed", "triage", "draft", "published", "withdrawn")
RESOLUTIONS = ("fix-merged-pr", "fix-commit", "pr-open", "wontfix", "duplicate", "closed-no-fix-ref",
               "advisory-published", "advisory-closed")
VERIFICATIONS = ("verified-fixed", "partial", "not-fixed", "unverified")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
# status -> date field stamped on the first change to it (time to answer / to fix)
STATUS_STAMP = {"answered": "answered_at", "fix-pr": "answered_at", "fixed": "fixed_at",
                "rejected": "answered_at", "closed": "answered_at"}


def stamp_status(e, new: str, when: str = None) -> None:
    """Sets the status and, the first time, the date field it stands for (answered_at /
    fixed_at, YYYY-MM-DD). A later status never moves a date that is already set; 'fixed'
    also counts as an answer."""
    e["status"] = new
    day = (when or now_iso())[:10]
    field = STATUS_STAMP.get(new)
    if field and not e.get(field):
        e[field] = day
    if new == "fixed" and not e.get("answered_at"):
        e["answered_at"] = day

# Marker in the draft: everything after it is the text that goes out.
TEXT_MARKER = "<!-- TEXT -->"


class DisclosureError(Exception):
    """Something the operator has to fix (exit 2)."""


class PolicyError(DisclosureError):
    """The check against the upstream security policy blocks (exit 1): field missing,
    required content not met, result not 'report', or the policy changed since
    the check."""


class AlreadySubmitted(DisclosureError):
    """The draft's ID is already in the register: it was submitted before and must not
    be submitted again (dry run: exit 0 with a notice, --submit: exit 1)."""

    def __init__(self, entry):
        self.entry = entry
        super().__init__(
            f"ALREADY SUBMITTED: {entry.get('id')} is in the register (channel {entry.get('channel')}, "
            f"reference {entry.get('reference')}, created {entry.get('created')}"
            + (f", {entry['url']}" if entry.get("url") else "") + ") - will not submit again")


# Where GitHub looks for a security policy, in GitHub's order of precedence: .github/,
# then the root, then docs/ (the first hit wins). Without a hit in the repository the
# organisation default from <owner>/.github applies (same paths).
SECURITY_PATHS = (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")
POLICY_RESULTS = ("report", "reclassify", "do-not-report")


# --------------------------------------------------------------------------- #
# Output and files
# --------------------------------------------------------------------------- #

def out(text: str = "") -> None:
    """Console output strictly ASCII (cp1252 consoles, Task Scheduler)."""
    sys.stdout.write(str(text).encode("ascii", "replace").decode("ascii") + "\n")
    sys.stdout.flush()


def err(text: str) -> None:
    sys.stderr.write(str(text).encode("ascii", "replace").decode("ascii") + "\n")
    sys.stderr.flush()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return json.loads(raw.decode("utf-8"))


def write_text(path: Path, text: str) -> None:
    """UTF-8 without BOM, LF, newline at the end."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n"):
        text += "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, indent=2, ensure_ascii=False))


def write_json_atomic(path: Path, data) -> None:
    """Write to a sibling file first, then os.replace - an abort leaves the old state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# gh
# --------------------------------------------------------------------------- #

def _gh(argv, stdin=None):
    try:
        proc = subprocess.run(["gh", *argv], capture_output=True, text=True,
                              encoding="utf-8", input=stdin)
    except FileNotFoundError as exc:
        raise DisclosureError("gh CLI not found") from exc
    return proc


class GhNotFound(Exception):
    """HTTP 404 - the thing does not exist (or, with forbidden_ok=True, HTTP 403 as well).
    An answer, not an operator error."""


def _gh_failed(path: str, message: str, forbidden_ok: bool):
    """Maps a failed GET: 404 -> GhNotFound; 403 -> DisclosureError (fail closed: a missing
    permission or a rate limit is NOT 'does not exist', otherwise the 'no SECURITY.md' gate
    would pass on it), unless the caller explicitly accepts 403 as 'not available'."""
    if "HTTP 404" in message or (forbidden_ok and "HTTP 403" in message):
        raise GhNotFound(message[:200])
    if "HTTP 403" in message:
        raise DisclosureError(f"gh api GET {path} forbidden (HTTP 403: permission or rate "
                              f"limit, not 'not found'): {message[:300]}")
    raise DisclosureError(f"gh api GET {path} failed: {message[:300]}")


def gh_get(path: str, forbidden_ok: bool = False):
    """GET against the GitHub API. Forces -X GET; never a field, never --input.
    Only HTTP 404 is GhNotFound; HTTP 403 is a DisclosureError unless forbidden_ok=True
    (for lists that are legitimately unavailable, e.g. disabled alerts)."""
    proc = _gh(["api", "-X", "GET", "-H", "Accept: application/vnd.github+json", path])
    if proc.returncode != 0:
        _gh_failed(path, (proc.stderr or proc.stdout or "").strip(), forbidden_ok)
    text = proc.stdout.strip()
    return json.loads(text) if text else None


def gh_get_list(path: str, max_items: int = 1000, forbidden_ok: bool = False):
    """GET with --paginate; every element separately (jq '.[]'), then capped.
    404/403 handling as in gh_get."""
    proc = _gh(["api", "-X", "GET", "--paginate", "-H", "Accept: application/vnd.github+json",
                path, "--jq", ".[]"])
    if proc.returncode != 0:
        _gh_failed(path, (proc.stderr or proc.stdout or "").strip(), forbidden_ok)
    items = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            items.append(json.loads(line))
            if len(items) >= max_items:
                break
    return items


def gh_logged_in() -> str:
    """Login of the signed-in account; DisclosureError if gh is not usable."""
    proc = _gh(["api", "-X", "GET", "user", "--jq", ".login"])
    if proc.returncode != 0 or not proc.stdout.strip():
        raise DisclosureError("gh is not logged in or not reachable: "
                              + (proc.stderr or "").strip()[:200])
    return proc.stdout.strip()


def gh_post(path: str, payload: dict, method: str = "POST"):
    """The ONLY writing gh path (POST; PATCH for closing own issues).
    Only from the submit tools, only after check_approval(). Payload via stdin
    (--input -), so that no text ends up on a command line or in a file."""
    if method not in ("POST", "PATCH"):
        raise DisclosureError(f"method {method} not allowed")
    proc = _gh(["api", "-X", method, "-H", "Accept: application/vnd.github+json",
                path, "--input", "-"], stdin=json.dumps(payload))
    if proc.returncode != 0:
        raise DisclosureError(f"gh api {method} {path} failed: "
                              + (proc.stderr or proc.stdout or "").strip()[:500])
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def check_repo(repo: str) -> str:
    if not repo or not REPO_RE.match(repo):
        raise DisclosureError(f"not a valid owner/name: {repo!r}")
    return repo


# --------------------------------------------------------------------------- #
# Draft format
# --------------------------------------------------------------------------- #

_JSON_BLOCK = re.compile(r"```json disclosure\s*\n(.*?)\n```", re.S)


def read_draft(path: Path):
    """(meta, text, raw bytes). meta = JSON block, text = everything after TEXT_MARKER.

    Format of a draft (Markdown):

        # internal heading (does NOT go out)
        internal notes ...

        ```json disclosure
        { "id": "...", "repo": "owner/name", "channel": "issue", ... }
        ```

        <!-- TEXT -->
        English text that goes out exactly like this
    """
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise DisclosureError(f"{path}: BOM - remove it first")
    if b"\r" in raw:
        raise DisclosureError(f"{path}: CR characters - convert the file to LF")
    content = raw.decode("utf-8")
    m = _JSON_BLOCK.search(content)
    if not m:
        raise DisclosureError(f"{path}: no ```json disclosure``` block")
    try:
        meta = json.loads(m.group(1))
    except json.JSONDecodeError as exc:
        raise DisclosureError(f"{path}: JSON block unreadable: {exc}") from exc
    # The marker must occur exactly once and AFTER the JSON block: a marker earlier (in the
    # internal notes or inside the JSON) would let a different text go out than the one
    # that was read and approved.
    count = content.count(TEXT_MARKER)
    if count == 0:
        raise DisclosureError(f"{path}: marker {TEXT_MARKER} missing")
    if count > 1:
        raise DisclosureError(f"{path}: marker {TEXT_MARKER} occurs {count} times - exactly once allowed")
    pos = content.index(TEXT_MARKER)
    if pos < m.end():
        raise DisclosureError(f"{path}: marker {TEXT_MARKER} comes before the end of the "
                              "```json disclosure``` block - it must follow the block")
    text = content[pos + len(TEXT_MARKER):].strip("\n")
    return meta, text, raw


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob_sha(raw: bytes) -> str:
    """SHA-1 of a git blob (like 'git hash-object') - checks a stored copy against
    the blob SHA reported by the GitHub API."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


# --------------------------------------------------------------------------- #
# Approvals: hash-bound, one-time
# --------------------------------------------------------------------------- #

APPROVAL_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


def _find(name: str, root_dir: Path, sub_dir: str, record):
    """Path of a per-record file: in the record's confidential folder if a record is given,
    otherwise wherever it already exists (root first, then every record), else in the root."""
    if record:
        return record_dirs(record)[1] / sub_dir / name
    if (root_dir / name).exists() or not records_enabled():
        return root_dir / name
    for d in sorted((_base(REGISTER_PRIVATE) / "repos").glob(f"*/disclosures/{sub_dir}")):
        if (d / name).exists():
            return d / name
    return root_dir / name


def approval_path(disclosure_id: str, record: str = None) -> Path:
    if not APPROVAL_ID_RE.match(disclosure_id or ""):
        raise DisclosureError(f"invalid disclosure ID: {disclosure_id!r}")
    return _find(f"{disclosure_id}.approval", APPROVALS, "approvals", record)


def check_approval(disclosure_id: str, raw: bytes, action: str):
    """(ok, reason). The file contains 'sha256=<hex>' and 'action=<action>'."""
    path = approval_path(disclosure_id)
    if not path.exists():
        try:
            shown = path.relative_to(ROOT).as_posix()
        except ValueError:
            shown = path.as_posix()
        return False, f"no approval file {shown}"
    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            values[k.strip().lower()] = v.strip()
    expected = values.get("sha256", "").lower()
    actual = sha256_bytes(raw)
    if expected != actual:
        return False, (f"hash differs (approval {expected[:12] or '-'}..., draft {actual[:12]}...): "
                       "the text was changed after the approval")
    if values.get("action", "") != action:
        return False, f"approval is for action={values.get('action', '-')}, not {action}"
    return True, "ok"


def consume_approval(disclosure_id: str) -> None:
    try:
        approval_path(disclosure_id).unlink()
    except FileNotFoundError:
        pass


def write_approval(disclosure_id: str, raw: bytes, action: str, note: str, record: str = "") -> Path:
    """record = the reviewed repository the draft belongs to ('' = the checker itself)."""
    path = approval_path(disclosure_id, record)
    write_text(path, "\n".join([
        "# One-time approval - deleted on submission.",
        "# Valid only for exactly this draft text (SHA-256).",
        f"action={action}",
        f"sha256={sha256_bytes(raw)}",
        f"granted={now_iso()}",
        f"note={note}",
    ]))
    return path


# --------------------------------------------------------------------------- #
# Codex cross-check of a disclosure text (optional, switched on in .env)
# --------------------------------------------------------------------------- #

CODEX_CHECK_KEYS = ("disclosure_codex_check", "disclosure_codex_model", "disclosure_codex_effort",
                    "disclosure_codex_channels", "disclosure_codex_timeout")
CODEX_CHECK_DEFAULTS = {"disclosure_codex_model": "gpt-6.1-sol", "disclosure_codex_effort": "medium"}
CODEX_CHECK_ON = ("on", "1", "true", "yes")
# Scope of a check switch: off | critical (only severity_class critical) | all ("on" = all)
SCOPES = ("off", "critical", "all")
# Channels that leave the machine as a report; reactions in the own repository are answers, not reports.
CODEX_CHECK_CHANNELS = ("issue", "comment", "advisory", "email")
CHECK_PASS = "CHECK: CONFIRMED"
CHECK_FAIL = "CHECK: CORRECTIONS NEEDED"


def _read_env_keys(env_file: Path, keys) -> dict:
    """Plain key=value lines of the .env, only the given keys, inline comments cut off.
    No vault resolution - these keys are switches, not secrets."""
    values = {}
    if not env_file.exists():
        return values
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k in keys:
            values[k] = v.split(" #", 1)[0].strip().strip('"').strip("'")
    return values


def _env_with_overrides(keys, env_file: Path = None) -> dict:
    values = _read_env_keys(env_file or ENV_FILE, keys)
    for k in keys:
        if os.environ.get(k):
            values[k] = os.environ[k].strip()
    return values


def _scope(value: str) -> str:
    v = (value or "").strip().lower()
    if v in CODEX_CHECK_ON:
        return "all"
    if v in SCOPES:
        return v
    if v:
        raise DisclosureError(f"check switch {value!r} - allowed on/off/critical/all")
    return "off"


def scope_applies(scope: str, meta) -> bool:
    return scope == "all" or (scope == "critical" and meta.get("severity_class") == "critical")


def codex_check_config(env_file: Path = None) -> dict:
    """{'enabled', 'scope', 'channels', 'model', 'effort', 'timeout'}. Environment variables win
    over the .env. disclosure_codex_check: on/all, critical (only critical findings) or off."""
    values = _env_with_overrides(CODEX_CHECK_KEYS, env_file)
    scope = _scope(values.get("disclosure_codex_check", ""))
    channels = tuple(c.strip() for c in values.get("disclosure_codex_channels", "").split(",") if c.strip()) \
        or CODEX_CHECK_CHANNELS
    unknown = [c for c in channels if c not in CODEX_CHECK_CHANNELS]
    if unknown:
        raise DisclosureError(f"disclosure_codex_channels: unknown {unknown} - allowed {CODEX_CHECK_CHANNELS}")
    model, effort = resolve_model(values.get("disclosure_codex_model"), values.get("disclosure_codex_effort"),
                                  "code-review", CODEX_CHECK_DEFAULTS["disclosure_codex_model"],
                                  CODEX_CHECK_DEFAULTS["disclosure_codex_effort"], env_file)
    return {
        "enabled": scope != "off", "scope": scope, "channels": channels,
        "model": model, "effort": effort,
        "timeout": int(values.get("disclosure_codex_timeout") or 1500),
    }


# --------------------------------------------------------------------------- #
# claudex: model from the claudex-loop role configuration (optional)
# --------------------------------------------------------------------------- #

CLAUDEX_KEYS = ("claudex_loop_dir", "claudex_finding_check", "claudex_finding_model", "claudex_finding_effort",
                "claudex_exposure_check", "claudex_exposure_model", "claudex_exposure_effort",
                "claudex_audit_mode", "claudex_audit_model", "claudex_audit_effort",
                "claudex_initial_audit")
_ROLE_CACHE = {}


def role_spec(role: str, env_file: Path = None):
    """(model, effort) from 'claudex_roles.py --spec <role>' of the claudex-loop checkout named in
    claudex_loop_dir, or (None, None). Our own tool, read-only; any failure = (None, None)."""
    loop = _env_with_overrides(("claudex_loop_dir",), env_file).get("claudex_loop_dir", "")
    if not loop:
        return None, None
    key = (loop, role)
    if key not in _ROLE_CACHE:
        script = Path(loop) / "scripts" / "claudex_roles.py"
        model = effort = None
        if script.is_file():
            try:
                r = subprocess.run([sys.executable, "-I", str(script), "--spec", role], capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=30, cwd=str(ROOT))
                m = re.search(r"model=(\S+)\s+effort=(\S+)", r.stdout or "")
                if r.returncode == 0 and m:
                    model, effort = m.group(1), m.group(2)
            except (OSError, subprocess.SubprocessError):
                pass
        _ROLE_CACHE[key] = (model, effort)
    return _ROLE_CACHE[key]


def resolve_model(model, effort, role, default_model, default_effort, env_file: Path = None):
    """Explicit .env value, else the claudex-loop role (claudex_loop_dir), else the default."""
    if model and effort:
        return model, effort
    r_model, r_effort = role_spec(role, env_file)
    return model or r_model or default_model, effort or r_effort or default_effort


# The two finding checks before a disclosure (codex_check.py finding / exposure). Both are bound
# to the FINDING (finding_digest), not to the wording: correcting the text does not invalidate
# them, changing the finding, severity, rating, reference commit or exposure field does.
FINDING_PASS = "FINDING: CONFIRMED"
FINDING_FAIL = ("FINDING: NOT CONFIRMED", "FINDING: SEVERITY WRONG")
EXPOSURE_UNSAFE = "EXPOSURE: UNSAFE"
EXPOSURE_SAFE = "EXPOSURE: SAFE"
FORMS = {
    # form: switch, model/effort keys, claudex-loop role, defaults, valid last lines
    "finding": {"switch": "claudex_finding_check", "model": "claudex_finding_model",
                "effort": "claudex_finding_effort", "role": "code-review", "default_scope": "off",
                "default_model": "gpt-6.1-sol", "default_effort": "medium",
                "verdicts": (FINDING_PASS,) + FINDING_FAIL, "label": "finding validation"},
    "exposure": {"switch": "claudex_exposure_check", "model": "claudex_exposure_model",
                 "effort": "claudex_exposure_effort", "role": "exposure-review", "default_scope": "off",
                 "default_model": "gpt-6.1-sol", "default_effort": "medium",
                 "verdicts": (EXPOSURE_UNSAFE, EXPOSURE_SAFE), "label": "exposure pass"},
}
FINDING_FIELDS = ("repo", "forge", "finding", "severity_class", "severity_reason", "upstream_ref",
                  "cvss_vector_string", "severity", "cwe_ids", "vulnerabilities", "exposure")
EXPOSURE_VALUES = {"network": EXPOSURE_UNSAFE, "local": EXPOSURE_SAFE}


def form_config(form: str, env_file: Path = None) -> dict:
    f = FORMS[form]
    values = _env_with_overrides(CLAUDEX_KEYS, env_file)
    scope = _scope(values.get(f["switch"]) or f["default_scope"])
    model, effort = resolve_model(values.get(f["model"]), values.get(f["effort"]), f["role"],
                                  f["default_model"], f["default_effort"], env_file)
    return {"form": form, "enabled": scope != "off", "scope": scope, "model": model, "effort": effort}


def audit_config(env_file: Path = None) -> dict:
    """Codex half of the initial audit in tool-review step 5 (the Claude sub-agent always runs):
    form (audit form of AGENTS.md via codex_ro.py) | audit (claudex-loop /audit) | both."""
    values = _env_with_overrides(CLAUDEX_KEYS, env_file)
    if values.get("claudex_initial_audit"):
        raise DisclosureError("claudex_initial_audit was renamed: use claudex_audit_mode=form|audit|both "
                              "(old value codex = form)")
    mode = (values.get("claudex_audit_mode") or "form").strip().lower()
    if mode not in ("form", "audit", "both"):
        raise DisclosureError(f"claudex_audit_mode={mode!r} - allowed form, audit, both")
    model, effort = resolve_model(values.get("claudex_audit_model"), values.get("claudex_audit_effort"),
                                  "audit", "gpt-6.1-sol", "medium", env_file)
    return {"mode": mode, "model": model, "effort": effort,
            "claudex_loop_dir": values.get("claudex_loop_dir") or ""}


def finding_digest(meta) -> str:
    """SHA-256 over the finding fields of the draft (canonical JSON) - not the text."""
    data = {k: meta.get(k) for k in FINDING_FIELDS if meta.get(k) not in (None, "", [])}
    return sha256_bytes(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def checks_dir(record: str = "") -> Path:
    """Folder of the Codex check records and outputs of a record ('' = root)."""
    return record_dirs(record)[1] / "checks" if record and records_enabled() else CHECKS


def form_check_path(disclosure_id: str, form: str, record: str = None) -> Path:
    if not APPROVAL_ID_RE.match(disclosure_id or ""):
        raise DisclosureError(f"invalid disclosure ID: {disclosure_id!r}")
    return _find(f"{disclosure_id}.{form}.check", CHECKS, "checks", record)


def read_form_check(disclosure_id: str, form: str) -> dict:
    path = form_check_path(disclosure_id, form)
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            values[k.strip().lower()] = v.strip()
    return values


def write_form_check(meta, form: str, cfg: dict, verdict: str, out_file: Path, source_sha: str,
                     thread_id: str = "", record: str = "") -> Path:
    path = form_check_path(meta["id"], form, record)
    write_text(path, "\n".join([
        f"# Codex {FORMS[form]['label']} - valid for exactly this finding (digest of the finding fields).",
        f"finding_digest={finding_digest(meta)}",
        f"source_sha={source_sha}",
        f"model={cfg['model']}",
        f"effort={cfg['effort']}",
        f"verdict={verdict}",
        f"output={out_file.resolve().relative_to(ROOT.resolve()).as_posix()}",
        f"output_sha256={sha256_bytes(out_file.read_bytes())}",
        f"thread_id={thread_id}",
        f"checked={now_iso()}",
    ]))
    return path


def check_form(meta, form: str, cfg: dict = None):
    """(ok, reason) of the finding validation or the exposure pass for this draft."""
    cfg = cfg or form_config(form)
    label = FORMS[form]["label"]
    if not cfg["enabled"] or meta.get("channel") not in CODEX_CHECK_CHANNELS or not scope_applies(cfg["scope"], meta):
        return True, f"{label} not required"
    rec = read_form_check(meta.get("id", ""), form)
    if not rec:
        return False, f"no Codex {label} for this finding"
    if rec.get("finding_digest", "").lower() != finding_digest(meta):
        return False, f"Codex {label} is for other finding fields (finding/severity/rating/ref/exposure changed)"
    if (rec.get("model"), rec.get("effort")) != (cfg["model"], cfg["effort"]):
        return False, (f"Codex {label} ran with {rec.get('model')}/{rec.get('effort')}, "
                       f"required {cfg['model']}/{cfg['effort']}")
    out_file = ROOT / rec.get("output", "")
    if not rec.get("output") or not out_file.is_file():
        return False, f"Codex output of the {label} is missing"
    data = out_file.read_bytes()
    if sha256_bytes(data) != rec.get("output_sha256", "").lower():
        return False, f"Codex output of the {label} was changed after the check"
    verdict = rec.get("verdict")
    if last_line(data.decode("utf-8", "replace")) != verdict:
        return False, f"Codex output of the {label} does not end with the recorded verdict"
    if form == "finding" and verdict != FINDING_PASS:
        return False, f"Codex {label} verdict: {verdict}"
    if form == "exposure":
        claimed = meta.get("exposure")
        if claimed is not None and EXPOSURE_VALUES.get(claimed) != verdict:
            return False, (f"draft says exposure={claimed!r}, the exposure pass says {verdict} - "
                           "correct the draft (or the severity) and run the finding checks again")
        if verdict == EXPOSURE_SAFE and meta.get("severity_class") == "critical" and not meta.get("exposure_override"):
            return False, ("exposure pass says EXPOSURE: SAFE (not reachable from outside) for a critical finding - "
                           "reclassify, or give 'exposure_override': '<reason>' in the draft")
    return True, "ok"


def check_claudex(meta, raw: bytes):
    """All Codex gates of a draft: [(ok, label, reason)] for text check, finding validation, exposure."""
    ok, reason = check_codex(meta, raw)
    res = [(ok, "text check", reason)]
    for form in FORMS:
        ok, reason = check_form(meta, form)
        res.append((ok, FORMS[form]["label"], reason))
    return res


def check_path(disclosure_id: str, record: str = None) -> Path:
    if not APPROVAL_ID_RE.match(disclosure_id or ""):
        raise DisclosureError(f"invalid disclosure ID: {disclosure_id!r}")
    return _find(f"{disclosure_id}.check", CHECKS, "checks", record)


def read_check(disclosure_id: str) -> dict:
    path = check_path(disclosure_id)
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            values[k.strip().lower()] = v.strip()
    return values


def write_check(disclosure_id: str, raw: bytes, cfg: dict, verdict: str, out_file: Path,
                thread_id: str = "", record: str = "") -> Path:
    path = check_path(disclosure_id, record)
    write_text(path, "\n".join([
        "# Codex cross-check of the disclosure text - valid only for exactly this draft (SHA-256).",
        f"sha256={sha256_bytes(raw)}",
        f"model={cfg['model']}",
        f"effort={cfg['effort']}",
        f"verdict={verdict}",
        f"output={out_file.resolve().relative_to(ROOT.resolve()).as_posix()}",
        f"output_sha256={sha256_bytes(out_file.read_bytes())}",
        f"thread_id={thread_id}",
        f"checked={now_iso()}",
    ]))
    return path


def last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1].strip("*` ") if lines else ""


def check_codex(meta, raw: bytes, cfg: dict = None):
    """(ok, reason). Without the switch in .env always ok. Otherwise a check record for exactly
    this draft hash, with the configured model/effort, verdict CONFIRMED, and an unchanged
    Codex output whose last line says so."""
    cfg = cfg or codex_check_config()
    if not cfg["enabled"] or meta.get("channel") not in cfg.get("channels", CODEX_CHECK_CHANNELS) \
            or not scope_applies(cfg.get("scope", "all"), meta):
        return True, "codex check not required"
    rec = read_check(meta.get("id", ""))
    if not rec:
        return False, "no Codex cross-check for this draft"
    if rec.get("sha256", "").lower() != sha256_bytes(raw):
        return False, "Codex cross-check is for an older version of the draft (hash differs)"
    if (rec.get("model"), rec.get("effort")) != (cfg["model"], cfg["effort"]):
        return False, (f"Codex cross-check ran with {rec.get('model')}/{rec.get('effort')}, "
                       f"required {cfg['model']}/{cfg['effort']}")
    if rec.get("verdict") != CHECK_PASS:
        return False, f"Codex cross-check verdict: {rec.get('verdict') or '-'}"
    out_file = ROOT / rec.get("output", "")
    if not rec.get("output") or not out_file.is_file():
        return False, "Codex output of the cross-check is missing"
    data = out_file.read_bytes()
    if sha256_bytes(data) != rec.get("output_sha256", "").lower():
        return False, "Codex output of the cross-check was changed after the check"
    if last_line(data.decode("utf-8", "replace")) != CHECK_PASS:
        return False, "Codex output does not end with " + CHECK_PASS
    return True, "ok"


# --------------------------------------------------------------------------- #
# Register
# --------------------------------------------------------------------------- #

def is_public(e) -> bool:
    """Publicly visible: issues/comments, and advisories after publishing (public=true).
    Submitted, unpublished advisories, mails and confidential issues (GitLab) are confidential."""
    if e.get("public") is True:
        return True
    return e.get("channel") in ("issue", "comment") and not e.get("confidential")


def is_under_private(path: Path) -> bool:
    try:
        Path(path).resolve().relative_to(PRIVATE.resolve())
        return True
    except ValueError:
        return False


def _shown(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_register():
    """All parts together: the root (the checker itself) and every record, public and
    confidential. An entry read from a record's file carries that record (field 'record')."""
    entries = []
    for path in register_files():
        data = load_json(path, [])
        if not isinstance(data, list):
            raise DisclosureError(f"{_shown(path)} is not a list")
        record = path.parent.parent.name if path not in (REGISTER, REGISTER_PRIVATE) else ""
        for e in data:
            if record and not e.get("record"):
                e["record"] = record
            entries.append(e)
    return entries


def register_file_of(e) -> Path:
    """The file an entry belongs in: its record (field 'record', '' = root), public or not."""
    pub, priv = record_dirs(e.get("record") or "")
    return (pub if is_public(e) else priv) / "register.json"


LOCK_STALE_SECONDS = 600
LOCK_WAIT_SECONDS = 5.0
_lock_depth = 0


@contextmanager
def register_lock():
    """Serialises writers of the register (lock file next to the confidential part, created
    with O_CREAT|O_EXCL). Re-entrant within the process, so that a caller can hold the lock
    over load + modify + save. A lock older than LOCK_STALE_SECONDS is taken over."""
    global _lock_depth
    if _lock_depth:
        _lock_depth += 1
        try:
            yield
        finally:
            _lock_depth -= 1
        return
    lock = REGISTER_PRIVATE.with_name("register.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + LOCK_WAIT_SECONDS
    while True:
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(f"pid={os.getpid()}\ntime={now_iso()}\n")
            break
        except FileExistsError:
            try:
                age = time.time() - lock.stat().st_mtime
            except FileNotFoundError:
                continue                       # released meanwhile: try again
            if age > LOCK_STALE_SECONDS:
                try:
                    lock.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.time() >= deadline:
                raise DisclosureError(
                    f"register is locked by another process ({lock.name}, {int(age)} s old) - "
                    "wait, or delete the file if no other tool is running "
                    f"(taken over automatically after {LOCK_STALE_SECONDS} s)")
            time.sleep(0.1)
    _lock_depth = 1
    try:
        yield
    finally:
        _lock_depth = 0
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def save_register(entries) -> None:
    """Splits by is_public(): nothing confidential ends up in the public part.
    Under the register lock, each part via temp file + os.replace. The public part is
    written first: if the process stops in between, an entry that moves to the public part
    ('publish') exists twice (visible in 'register.py check') but is never lost."""
    with register_lock():
        groups = {}
        for e in entries:
            groups.setdefault(register_file_of(e), []).append(e)
        for path in register_files():          # files that existed keep existing (maybe empty)
            groups.setdefault(path, [])
        groups.setdefault(REGISTER, [])        # the root public part is always written
        private_base = _base(REGISTER_PRIVATE) if records_enabled() else None

        def is_private_file(path):
            return path == REGISTER_PRIVATE or (private_base is not None and private_base in path.parents)
        for path in sorted(groups, key=lambda x: (is_private_file(x), str(x))):   # public parts first
            if groups[path] or path.exists() or path == REGISTER:
                write_json_atomic(path, groups[path])


def load_watch_config():
    """disclosures/watch_config.json, extended by private/disclosures/watch_config.local.json
    (lists are concatenated, objects merged) - internals only there."""
    base = load_json(WATCH_CONFIG, {}) or {}
    local = load_json(WATCH_CONFIG_LOCAL, {}) or {}
    for k, v in local.items():
        if isinstance(v, list) and isinstance(base.get(k), list):
            base[k] = base[k] + [x for x in v if x not in base[k]]
        elif isinstance(v, dict) and isinstance(base.get(k), dict):
            for rk, rv in v.items():
                if isinstance(rv, dict) and isinstance(base[k].get(rk), dict):
                    base[k][rk] = {**base[k][rk], **rv}
                else:
                    base[k][rk] = rv
        else:
            base[k] = v
    return base


def load_vault_env():
    """Module vault_env from UJC_VAULT_ENV (path to the file vault_env.py or its folder)."""
    location = os.environ.get("UJC_VAULT_ENV", "")
    if not location:
        raise DisclosureError("UJC_VAULT_ENV is not set (path to vault_env.py or its folder)")
    p = Path(location)
    folder = p.parent if p.suffix == ".py" else p
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
    try:
        import vault_env
    except ImportError as exc:
        raise DisclosureError("vault_env cannot be loaded from UJC_VAULT_ENV") from exc
    return vault_env


def next_id(entries, repo_short: str) -> str:
    prefix = f"{repo_short}-"
    numbers = [int(e["id"][len(prefix):]) for e in entries
               if str(e.get("id", "")).startswith(prefix) and e["id"][len(prefix):].isdigit()]
    return f"{prefix}{(max(numbers) + 1) if numbers else 1:02d}"
