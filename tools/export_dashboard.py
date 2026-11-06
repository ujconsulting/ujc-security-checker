#!/usr/bin/env python3
"""Export the checker's metadata for a dashboard ingest (generic, standard library only).

Reads ONLY:
  - the header table of every record README (repos/<record>/README.md: Upstream, Reviewed
    version, Verdict, Recommendation; the full header from private/records/<record>/record-full.md
    if present: Audited upstream state, Fork, Latest verdict),
  - the ledgers (private/ledger/, see tools/ledger.py: reviews, runs, findings),
  - the disclosure registers (tools/disclosures/register.py), field by field.
Never free text: no finding titles, severity_reason, notes, drafts, approvals, mail, egress or
infrastructure data. It writes nothing below private/.

Tables (one JSON payload: {"plugin_version": ..., "tabellen": {<table>: [rows]}}):
  sec_review           one row per record: name, kind, version, source, fork, verdict,
                       verdict_raw, decision, decided_at, usage
  sec_run              review runs
  sec_disclosure       disclosures: dates, status, channel, severity; for UNPUBLISHED ones only
                       a pseudonymous id (c-<8 hex>), a placeholder for the record
                       (confidential-<8 hex>), severity, status, created, due_by and channel
  sec_finding          finding metadata; location only for published findings
  sec_disclosure_week  counts per week of 'created' x current status (no names)
  sec_cleartext        placeholder -> real name / id / CVE / GHSA - ONLY with --cleartext
  manifest             delivered_at, schema_version, cleartext, exporter_version

Placeholders are an HMAC of the name with a private salt (private/ledger/salt, created with
"python tools/ledger.py salt"), so they stay the same across runs and tables. The location and
search terms of unpublished findings are never exported, not even with --cleartext.

    python tools/export_dashboard.py [--out FILE] [--cleartext] [--summary]
        writes the payload to FILE (or $UJC_DASHBOARD_OUT, else stdout); dry run - sends nothing
    python tools/export_dashboard.py --send [--cleartext]
        POSTs the payload to the ingest URL ($UJC_DASHBOARD_URL, else "ingest_url" in
        private/dashboard.json) with the token from $UJC_DASHBOARD_TOKEN or the key
        UJC_DASHBOARD_TOKEN in .env. https everywhere; plain http only with allow_http_lan
        (default on; key in private/dashboard.json or UJC_DASHBOARD_ALLOW_HTTP_LAN=0/1) and only to
        local targets: 10/8, 172.16/12, 192.168/16, 127/8, fc00::/7, ::1, or a name without a dot
        or ending in .lan/.local/.internal/.home.arpa. No user information, query or fragment in
        the URL; redirects are not followed; system proxies are ignored. With --cleartext
        only https (plain http at most to the own loopback).
    python tools/export_dashboard.py --self-test

Every run validates the payload (declared columns, value lists, lengths, location form) and
leak-scans every value (credentials, local paths, internal addresses and names) - any error
stops the export. Exit 0 ok, 1 validation or leak error / ingest refused, 2 operator error.
Output ASCII only.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "disclosures"))
import ledger  # noqa: E402

PLUGIN_VERSION = "1.0.0"
SCHEMA_VERSION = 1
EXPORTER_VERSION = "1.0.0"
CHANNELS = ("issue", "comment", "advisory", "email")
STATUS = ("open", "answered", "fix-pr", "fixed", "rejected", "closed")
SEVERITY_CLASSES = ("critical", "non-critical")
# same lists as tools/disclosures/_common.py (the self-test compares them)
UPSTREAM_STATES = ("open", "closed", "triage", "draft", "published", "withdrawn")
RESOLUTIONS = ("fix-merged-pr", "fix-commit", "pr-open", "wontfix", "duplicate", "closed-no-fix-ref",
               "advisory-published", "advisory-closed")
VERIFICATIONS = ("verified-fixed", "partial", "not-fixed", "unverified")

# Declaration of the tables: column -> (type, max length, nullable, allowed values or None).
# It mirrors the plugin manifest of the dashboard; the ingest refuses everything else (422).
T, D, TS, I, B = "text", "date", "timestamptz", "integer", "boolean"
DECL = {
    "sec_review": {
        "name": (T, 200, False, None), "kind": (T, 16, False, ledger.KINDS),
        "version": (T, 64, False, None), "source": (T, 200, True, None), "fork": (B, 0, False, None),
        "verdict": (T, 24, False, ledger.VERDICTS), "verdict_raw": (T, 80, True, None),
        "decision": (T, 32, True, ledger.DECISIONS), "decided_at": (D, 0, True, None),
        "usage": (T, 64, True, None)},
    "sec_run": {
        "record": (T, 200, False, None), "round": (I, 0, False, None),
        "step": (T, 24, False, ledger.STEPS), "reviewer": (T, 8, False, ledger.REVIEWERS),
        "model": (T, 64, True, None), "effort": (T, 16, True, None),
        "started_at": (TS, 0, False, None), "ended_at": (TS, 0, True, None),
        "verdict": (T, 24, True, ledger.VERDICTS), "commit": (T, 40, True, None),
        "thread_id": (T, 64, True, None)},
    "sec_disclosure": {
        "id": (T, 32, False, None), "record": (T, 200, False, None),
        "channel": (T, 16, False, CHANNELS), "status": (T, 16, False, STATUS),
        "severity_class": (T, 16, False, SEVERITY_CLASSES), "severity": (T, 16, True, ledger.SEVERITIES),
        "category": (T, 32, True, ledger.CATEGORIES), "created": (D, 0, False, None),
        "last_checked": (D, 0, True, None), "due_by": (D, 0, True, None),
        "embargo_until": (D, 0, True, None), "published_at": (D, 0, True, None),
        "answered_at": (D, 0, True, None), "fixed_at": (D, 0, True, None),
        "response_days": (I, 0, True, None), "cve": (T, 32, True, None), "ghsa": (T, 32, True, None),
        # how upstream dealt with it (watch, upstream's account) and what our check of the code found
        "upstream_state": (T, 16, True, UPSTREAM_STATES), "closed_at": (D, 0, True, None),
        "resolution": (T, 24, True, RESOLUTIONS), "fix_commit": (T, 40, True, None),
        "fix_release": (T, 64, True, None), "closed_via_bot": (B, 0, True, None),
        "verification": (T, 16, True, VERIFICATIONS), "verified_at": (D, 0, True, None)},
    "sec_finding": {
        "record": (T, 200, False, None), "finding_id": (T, 32, False, None),
        "severity": (T, 16, False, ledger.SEVERITIES), "category": (T, 32, False, ledger.CATEGORIES),
        "status": (T, 16, False, ledger.FINDING_STATUS), "public": (B, 0, False, None),
        "disclosure_id": (T, 32, True, None), "location": (T, 200, True, None)},
    "sec_disclosure_week": {
        "week": (D, 0, False, None), "severity_class": (T, 16, False, SEVERITY_CLASSES),
        "channel": (T, 16, False, CHANNELS), "status": (T, 16, False, STATUS), "count": (I, 0, False, None)},
    "sec_cleartext": {
        "placeholder": (T, 64, False, None), "real_id": (T, 200, False, None),
        "disclosure_id": (T, 64, True, None), "record": (T, 200, True, None),
        "cve": (T, 32, True, None), "ghsa": (T, 32, True, None)},
    "manifest": {
        "delivered_at": (TS, 0, False, None), "schema_version": (I, 0, False, None),
        "cleartext": (B, 0, False, None), "exporter_version": (T, 32, False, None)},
}
# Fields a row of an UNPUBLISHED disclosure may carry with a value (the rest is null).
CONFIDENTIAL_DISCLOSURE_FIELDS = {"id", "record", "channel", "status", "severity_class", "severity",
                                  "created", "due_by"}
# Leak scan kinds that do not apply to this internal export: tool and model names are the
# subject of sec_run, and own fork version suffixes are the subject of sec_review.
LEAK_KINDS_IGNORED = {"AI hint", "own name"}


class ExportError(Exception):
    """Something the operator has to fix (exit 2)."""


def out(text: str = "") -> None:
    sys.stdout.write(str(text).encode("ascii", "replace").decode("ascii") + "\n")
    sys.stdout.flush()


def err(text: str) -> None:
    sys.stderr.write(str(text).encode("ascii", "replace").decode("ascii") + "\n")
    sys.stderr.flush()


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #

def checker_root() -> Path:
    return Path(os.environ.get("UJC_CHECKER_ROOT") or HERE.parent)


_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|\s*$", re.M)


def readme_table(path: Path, whole: bool = False) -> dict:
    """{row name: value} of the first table of a record README (whole=True: all table rows of
    the file, first occurrence wins - for the private notes, where the rows sit further down)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = {}
    for key, value in _ROW.findall(text if whole else text.split("\n## ", 1)[0]):
        rows.setdefault(key.strip(), value)
    return rows


def _first_tick(text: str):
    m = re.search(r"`([^`]+)`", text or "")
    return m.group(1) if m else None


def _latest_verdict(text: str):
    """The LAST verdict quote of the 'Latest verdict' row: a record with a hardened copy names
    the upstream verdict first and the copy's current one last ("upstream as shipped:
    `VERDICT: DO NOT USE`; hardened copy: `FINAL TEST: APPROVED WITH CONDITIONS`")."""
    quotes = [q for q in re.findall(r"`([^`]+)`", text or "")
              if re.match(r"^\s*(VERDICT|FINAL TEST)\s*:|^\s*DO NOT USE\s*$", q, re.I)]
    return quotes[-1] if quotes else None


def record_table(root: Path, record: str) -> dict:
    """Header rows of a record: the summary README (repos/<record>/README.md: Upstream, Reviewed
    version, Reviewed on, Verdict, Recommendation ...) overlaid with the full header of
    private/records/<record>/record-full.md if that exists (Audited upstream state, Fork,
    Latest verdict ...). Row names of the summary and of the old format are both understood."""
    tab = {}
    readme = root / "repos" / record / "README.md"
    if readme.is_file():
        tab.update(readme_table(readme))
    full = root / "private" / "records" / record / "record-full.md"
    if full.is_file():
        tab.update(readme_table(full))
    return tab


def public_records(root: Path) -> set:
    return {p.parent.name for p in (root / "repos").glob("*/README.md")}


def load_salt(root: Path) -> bytes:
    path = ledger.ledger_dir() / "salt"
    if not path.is_file():
        raise ExportError(f"no salt - create it once: python tools/ledger.py salt ({path.name} in the ledger folder)")
    salt = path.read_text(encoding="ascii").strip()
    if not re.match(r"^[0-9a-f]{32,128}$", salt):
        raise ExportError("salt file is not hex (32-128 characters)")
    return salt.encode("ascii")


class Names:
    """Placeholders: confidential-<8 hex> for a record, c-<8 hex> for an unpublished
    disclosure id. Collects the mapping for sec_cleartext; two names on one placeholder abort."""

    def __init__(self, salt: bytes):
        self.salt = salt
        self.map = {}

    def _tag(self, kind: str, value: str) -> str:
        return hmac.new(self.salt, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:8]

    def _keep(self, placeholder: str, row: dict) -> str:
        old = self.map.get(placeholder)
        if old is not None and old["real_id"] != row["real_id"]:
            raise ExportError(f"placeholder collision on {placeholder} - change the salt")
        self.map.setdefault(placeholder, row)
        return placeholder

    def record(self, record: str) -> str:
        return self._keep(f"confidential-{self._tag('record', record)}",
                          {"real_id": record, "disclosure_id": None, "record": record, "cve": None, "ghsa": None})

    def disclosure(self, e: dict, record: str) -> str:
        return self._keep(f"c-{self._tag('id', e['id'])}",
                          {"real_id": e["id"], "disclosure_id": e["id"], "record": record,
                           "cve": e.get("cve"), "ghsa": _ghsa(e)})

    def rows(self):
        return [{"placeholder": p, **row} for p, row in sorted(self.map.items())]


def _ghsa(e) -> str:
    if e.get("ghsa"):
        return e["ghsa"]
    if e.get("channel") == "advisory" and str(e.get("reference", "")).startswith("GHSA-"):
        return str(e["reference"]).split("#", 1)[0]
    return None


def _day(value):
    """YYYY-MM-DD of an ISO value (date or timestamp), else None."""
    if not value:
        return None
    s = str(value)
    try:
        if len(s) == 10:
            return date.fromisoformat(s).isoformat()
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def _due(e):
    if e.get("due_by"):
        return _day(e["due_by"])
    from disclosure_watch import deadline_due
    d = deadline_due(e)
    return d.date().isoformat() if d else None


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #

def build(cleartext: bool = False, now: str = None) -> dict:
    import _common
    root = checker_root()
    names = Names(load_salt(root))
    publics = public_records(root)
    reviews = {r["record"]: r for r in ledger.load_reviews()}
    records = sorted(publics | set(reviews))

    def rec_name(record, confidential=False):
        return names.record(record) if confidential or record not in publics else record

    # sec_review: facts from the README table, decisions from the ledger
    sec_review = []
    for record in records:
        lr = reviews.get(record) or {}
        tab = record_table(root, record)
        if not lr.get("kind"):
            raise ExportError(f"record {record}: no kind in the ledger - python tools/ledger.py review set {record} --kind ...")
        public = record in publics
        upstream = _first_tick(tab.get("Upstream", ""))
        # The own version (fork / hardened copy) is documented only privately
        # (private/repos/<record>/README-own-version.md); its rows win over the public upstream
        # rows. The export goes to an internal dashboard; this never lands in a public file.
        own = root / "private" / "repos" / record / "README-own-version.md"
        own_tab = readme_table(own, whole=True) if own.is_file() else {}
        fork_cell = (own_tab.get("Fork") or own_tab.get("Fork state") or tab.get("Fork", "")).strip().lower()
        verdict_cell = tab.get("Latest verdict", "") or tab.get("Verdict on upstream", "") or tab.get("Verdict", "")
        verdict_raw = (_latest_verdict(own_tab.get("Latest verdict", ""))
                       or _latest_verdict(verdict_cell)
                       or _first_tick(verdict_cell))      # summary format: `USABLE WITH CONDITIONS`
        sec_review.append({
            "name": rec_name(record),
            "kind": lr["kind"],
            "version": ((_first_tick(tab.get("Audited upstream state", "") or tab.get("Reviewed version", "")) or "")[:64]) if public else "",
            "source": (f"https://github.com/{upstream}" if public and upstream and ":" not in upstream else None),
            "fork": bool(fork_cell) and not fork_cell.startswith(("no fork", "-", "none")),
            "verdict": ledger.map_verdict(verdict_raw) or "pending",
            "verdict_raw": (verdict_raw or "")[:80] or None,
            "decision": lr.get("decision"),
            "decided_at": lr.get("decided_at"),
            "usage": lr.get("usage"),
        })

    sec_run = [{
        "record": rec_name(r["record"]), "round": r["round"], "step": r["step"], "reviewer": r["reviewer"],
        "model": r.get("model"), "effort": r.get("effort"), "started_at": r["started_at"],
        "ended_at": r.get("ended_at"), "verdict": r.get("verdict"), "commit": r.get("commit"),
        "thread_id": r.get("thread_id")} for r in ledger.load_runs()]

    # sec_disclosure
    register = _common.load_register()
    by_id = {e.get("id"): e for e in register}
    sec_disclosure, weeks = [], {}
    for e in register:
        record = e.get("record") or "checker"
        public = _common.is_public(e)
        created = _day(e.get("created"))
        row = {k: None for k in DECL["sec_disclosure"]}
        row.update({
            "channel": e.get("channel"), "status": e.get("status"),
            "severity_class": e.get("severity_class"), "severity": e.get("severity"),
            "created": created, "due_by": _due(e)})
        if public:
            row.update({
                "id": e["id"], "record": rec_name(record),
                "category": e.get("category"), "last_checked": _day(e.get("last_checked")),
                "embargo_until": _day(e.get("embargo_until")),
                "published_at": _day(e.get("published_at")) or created,
                "answered_at": _day(e.get("answered_at")), "fixed_at": _day(e.get("fixed_at")),
                "response_days": e.get("response_days"), "cve": e.get("cve"), "ghsa": _ghsa(e),
                "upstream_state": e.get("upstream_state"), "closed_at": _day(e.get("closed_at")),
                "resolution": e.get("resolution"), "fix_commit": e.get("fix_commit"),
                "fix_release": e.get("fix_release"), "closed_via_bot": e.get("closed_via_bot"),
                "verification": e.get("verification"), "verified_at": _day(e.get("verified_at"))})
        else:
            row.update({"id": names.disclosure(e, record), "record": names.record(record)})
            for k in DECL["sec_disclosure"]:
                if k not in CONFIDENTIAL_DISCLOSURE_FIELDS:
                    row[k] = None
        sec_disclosure.append(row)
        if created:
            d = date.fromisoformat(created)
            key = ((d - timedelta(days=d.weekday())).isoformat(), e.get("severity_class"), e.get("channel"),
                   e.get("status"))
            weeks[key] = weeks.get(key, 0) + 1
    sec_disclosure_week = [{"week": w, "severity_class": s, "channel": c, "status": st, "count": n}
                           for (w, s, c, st), n in sorted(weeks.items())]

    # sec_finding: unpublished = marked confidential in the ledger, linked to an unpublished
    # disclosure, or of a record without a public README
    sec_finding = []
    for f in ledger.load_findings():
        disc = by_id.get(f.get("disclosure_id")) if f.get("disclosure_id") else None
        public = (not f.get("confidential") and f["record"] in publics
                  and (disc is None or _common.is_public(disc)))
        if f.get("disclosure_id") and disc is None:
            raise ExportError(f"finding {f['record']}/{f['finding_id']}: disclosure {f['disclosure_id']} not in the register")
        # an unpublished finding never carries a real disclosure id, not even of a published
        # disclosure: next to the record placeholder it would reveal which record that is
        if disc is None:
            disc_id = None
        elif public:
            disc_id = disc["id"]
        else:
            disc_id = names.disclosure(disc, disc.get("record") or "checker")
        sec_finding.append({
            "record": rec_name(f["record"], not public), "finding_id": f["finding_id"],
            "severity": f["severity"], "category": f["category"], "status": f["status"],
            "public": public, "disclosure_id": disc_id,
            "location": f.get("location") if public else None})

    tables = {"sec_review": sec_review, "sec_run": sec_run, "sec_disclosure": sec_disclosure,
              "sec_finding": sec_finding, "sec_disclosure_week": sec_disclosure_week}
    if cleartext:
        tables["sec_cleartext"] = names.rows()
    tables["manifest"] = [{"delivered_at": now or ledger.now_iso(), "schema_version": SCHEMA_VERSION,
                           "cleartext": bool(cleartext), "exporter_version": EXPORTER_VERSION}]
    return {"plugin_version": PLUGIN_VERSION, "tabellen": tables}


# --------------------------------------------------------------------------- #
# Validation and leak scan
# --------------------------------------------------------------------------- #

def _type_ok(typ, value) -> bool:
    if typ == B:
        return isinstance(value, bool)
    if typ == I:
        return isinstance(value, int) and not isinstance(value, bool)
    if typ == D:
        return isinstance(value, str) and _day(value) == value
    if typ == TS:
        return isinstance(value, str) and ledger.parse_iso(value) is not None
    return isinstance(value, str)


def validate(payload: dict) -> list:
    errors = []
    if set(payload) != {"plugin_version", "tabellen"}:
        errors.append("payload: top-level keys must be plugin_version and tabellen")
    for table, rows in (payload.get("tabellen") or {}).items():
        decl = DECL.get(table)
        if decl is None:
            errors.append(f"{table}: not a declared table")
            continue
        for nr, row in enumerate(rows, 1):
            if set(row) != set(decl):
                errors.append(f"{table} row {nr}: columns differ from the declaration "
                              f"(missing {sorted(set(decl) - set(row))}, extra: {len(set(row) - set(decl))})")
                continue
            for col, (typ, maxlen, nullable, allowed) in decl.items():
                v = row[col]
                if v is None:
                    if not nullable:
                        errors.append(f"{table} row {nr}: {col} must not be null")
                    continue
                if not _type_ok(typ, v):
                    errors.append(f"{table} row {nr}: {col} has the wrong type")
                elif typ == T and len(v) > maxlen:
                    errors.append(f"{table} row {nr}: {col} longer than {maxlen}")
                elif allowed is not None and v not in allowed:
                    errors.append(f"{table} row {nr}: {col} not in its value list")
            if table == "sec_finding" and row.get("location") is not None and not ledger.location_ok(row["location"]):
                errors.append(f"sec_finding row {nr}: location is not a relative path of the reviewed project")
            if table == "sec_finding" and not row.get("public") and row.get("location") is not None:
                errors.append(f"sec_finding row {nr}: location of an unpublished finding")
            if table == "sec_review" and row.get("usage"):
                if any(u not in ledger.USAGE for u in row["usage"].split(",")):
                    errors.append(f"sec_review row {nr}: usage not in its value list")
            if table == "sec_disclosure" and str(row.get("id", "")).startswith("c-"):
                extra = [k for k, v in row.items() if v is not None and k not in CONFIDENTIAL_DISCLOSURE_FIELDS]
                if extra:
                    errors.append(f"sec_disclosure row {nr}: unpublished disclosure carries {extra}")
    return errors


def leak_errors(payload: dict) -> list:
    """Leak scan of every string value (one value per line): credentials, local paths,
    internal addresses and names, mail addresses. The location column is validated by form."""
    import leak_scan
    values = []
    for table, rows in payload["tabellen"].items():
        for row in rows:
            for col, v in row.items():
                if isinstance(v, str) and not (table == "sec_finding" and col == "location"):
                    values.append(v)
    res = []
    for level, kind, nr, _match in leak_scan.scan("\n".join(values)):
        if level == "ERROR" and kind not in LEAK_KINDS_IGNORED:
            res.append(f"value {nr}: {kind}")
    for nr, v in enumerate(values, 1):
        if re.search(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,}", v) and not v.startswith("https://"):
            res.append(f"value {nr}: mail address")
    return res


# --------------------------------------------------------------------------- #
# Send
# --------------------------------------------------------------------------- #

# Plain http is allowed only for a fixed list of local targets (internal operation, often without
# TLS); everything else needs https. Names: without a dot, or with one of these endings.
# public-check: begin-allow internal  (private address ranges, not addresses of this operation)
HTTP_LAN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"))
# public-check: end-allow
HTTP_LAN_SUFFIXES = (".lan", ".local", ".internal", ".home.arpa")


def http_lan_host(host: str) -> bool:
    """True if plain http to this host is acceptable: a literal address inside HTTP_LAN_NETS
    (IPv4-mapped, 6to4, Teredo, NAT64, link-local, CGNAT and the like are not inside), or a
    name without a dot or with a local ending."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", host):
            return False
        return "." not in host or host.endswith(HTTP_LAN_SUFFIXES)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return False
    return any(addr.version == n.version and addr in n for n in HTTP_LAN_NETS)


def _allow_http_lan(cfg: dict) -> bool:
    """Option allow_http_lan (default on): UJC_DASHBOARD_ALLOW_HTTP_LAN=0/1 wins over the key
    allow_http_lan in private/dashboard.json. Switch it off for an external ingest."""
    env = os.environ.get("UJC_DASHBOARD_ALLOW_HTTP_LAN")
    if env is not None and env.strip():
        return env.strip().lower() in ("1", "on", "true", "yes")
    value = cfg.get("allow_http_lan", True)
    return value is True or str(value).lower() in ("1", "on", "true", "yes")


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address((host or "").strip("[]")).is_loopback
    except ValueError:
        return False


def check_url(url: str, allow_http_lan: bool = True, cleartext: bool = False) -> str:
    """https anywhere; plain http only to local targets with allow_http_lan - and never for a
    payload with sec_cleartext (embargoed names, CVE, GHSA), except to the own loopback."""
    u = urlsplit(url)
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise ExportError("the ingest URL must not carry user information")
    if u.query or u.fragment or "?" in url or "#" in url:
        raise ExportError("the ingest URL must not carry a query or fragment")
    if not u.hostname:
        raise ExportError("the ingest URL has no host")
    if u.scheme == "https":
        return url
    if u.scheme == "http" and cleartext and not _loopback(u.hostname):
        raise ExportError("--cleartext carries embargoed names: https only (plain http only to the own loopback)")
    if u.scheme == "http" and allow_http_lan and http_lan_host(u.hostname):
        return url
    raise ExportError("the ingest URL must be https (plain http only for local targets with "
                      "allow_http_lan on)")


def _target(cleartext: bool = False):
    root = checker_root()
    cfg = {}
    cfg_file = root / "private" / "dashboard.json"
    if cfg_file.is_file():
        cfg = json.loads(cfg_file.read_text(encoding="utf-8")) or {}
    url = os.environ.get("UJC_DASHBOARD_URL") or cfg.get("ingest_url")
    if not url:
        raise ExportError("no ingest URL: set UJC_DASHBOARD_URL or ingest_url in private/dashboard.json")
    url = check_url(url, _allow_http_lan(cfg), cleartext)
    token = os.environ.get("UJC_DASHBOARD_TOKEN")
    if not token:
        import _common
        token = _common._read_env_keys(root / ".env", ("UJC_DASHBOARD_TOKEN",)).get("UJC_DASHBOARD_TOKEN")
    if not token:
        raise ExportError("no token: set UJC_DASHBOARD_TOKEN (environment or .env)")
    return url, token


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: the token goes only to the configured URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    # empty ProxyHandler: system and environment proxies are ignored, the token never passes
    # through a proxy
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def send(payload: dict, url: str, token: str, attempts: int = 4) -> int:
    body = json.dumps(payload, ensure_ascii=True).encode("ascii")
    opener = _opener()
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=60) as resp:
                answer = resp.read(65536).decode("utf-8", "replace")
                out(f"OK: ingest answered {resp.status}: {answer[:300]}")
                return 0
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < attempts:
                wait = exc.headers.get("Retry-After") if exc.code == 429 else "5"
                wait = int(wait) if str(wait or "").isdigit() else 5
                err(f"NOTE: ingest {exc.code}, retry in {min(wait, 120)} s ({attempt}/{attempts})")
                time.sleep(min(wait, 120))
                continue
            detail = exc.read(2048).decode("utf-8", "replace") if exc.fp else ""
            err(f"ERROR: ingest refused with {exc.code}: {detail[:300]}")
            return 1
        except urllib.error.URLError as exc:
            err(f"ERROR: ingest not reachable: {exc.reason}")
            return 1
    return 1


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _raises(fn) -> bool:
    try:
        fn()
    except ExportError:
        return True
    return False


# public-check: begin-allow embargo,internal  (self-test fixtures: invented ids, K numbers and paths)
def self_test() -> int:
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import _common

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    check("value lists match _common", _common.SEVERITIES == ledger.SEVERITIES
          and _common.CATEGORIES == ledger.CATEGORIES and _common.STATUS_VALUES == STATUS
          and set(_common.CHANNELS) == set(CHANNELS) and _common.SEVERITY_CLASSES == SEVERITY_CLASSES
          and _common.UPSTREAM_STATES == UPSTREAM_STATES and _common.RESOLUTIONS == RESOLUTIONS
          and _common.VERIFICATIONS == VERIFICATIONS)
    names = ("ROOT", "PRIVATE", "REGISTER", "REGISTER_PRIVATE")
    saved = {n: getattr(_common, n) for n in names}
    saved_env = {k: os.environ.get(k) for k in ("UJC_CHECKER_ROOT", "UJC_LEDGER_DIR", "UJC_DASHBOARD_URL",
                                                 "UJC_DASHBOARD_TOKEN", "UJC_DASHBOARD_ALLOW_HTTP_LAN")}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        try:
            os.environ["UJC_CHECKER_ROOT"] = str(root)
            os.environ["UJC_LEDGER_DIR"] = str(root / "private" / "ledger")
            _common.ROOT, _common.PRIVATE = root, root / "private"
            _common.REGISTER = root / "disclosures" / "register.json"
            _common.REGISTER_PRIVATE = root / "private" / "disclosures" / "register.json"
            (root / "repos" / "tool" / "reviews").mkdir(parents=True)
            (root / "repos" / "tool" / "README.md").write_text(
                "# tool\n\n| | |\n|---|---|\n| Upstream | `acme/tool` - license MIT |\n"
                "| Audited upstream state | tag `v1.2.3` = `abc1234` |\n| Fork | `tool-x` (private) |\n"
                "| Latest verdict | `FINAL TEST: NOT APPROVED` - round 04 |\n\n## History\n", encoding="utf-8")
            base = {"repo": "acme/tool", "finding": "SECRET-TITLE", "severity_class": "critical",
                    "severity_reason": "SECRET-REASON", "url": "https://github.com/acme/tool/issues/1",
                    "created": "2026-10-07T10:00:00Z", "account": "someone", "upstream_ref": "main@x",
                    "last_checked": "2026-10-12T00:00:00Z", "notes": "mail me at a.b@example.org",
                    "record": "tool", "response_days": 7}
            pub = {**base, "id": "tool-01", "channel": "issue", "reference": "1", "status": "answered",
                   "answered_at": "2026-10-09", "severity": "high", "category": "injection",
                   "upstream_state": "closed", "closed_at": "2026-10-11", "resolution": "fix-commit",
                   "fix_commit": "abc1234", "fix_release": "v1.2.4", "closed_via_bot": True,
                   "verification": "verified-fixed", "verified_at": "2026-10-14"}
            conf = {**base, "id": "tool-K1", "channel": "advisory", "reference": "GHSA-2345-6789-cfgh",
                    "status": "open", "cve": "CVE-2026-12345", "severity": "critical",
                    "url": "https://github.com/acme/tool/security/advisories/GHSA-2345-6789-cfgh"}
            for path, rows in (((root / "private/records/tool/disclosures/register.json"), [pub]),
                               ((root / "private/repos/tool/disclosures/register.json"), [conf]),
                               (_common.REGISTER, []), (_common.REGISTER_PRIVATE, [])):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(rows), encoding="utf-8")
            ld = ledger.ledger_dir()
            (ld / "findings").mkdir(parents=True)
            (ld / "salt").write_text("0123456789abcdef0123456789abcdef\n", encoding="ascii")
            ledger.write_jsonl(ld / "reviews.jsonl", [{"record": "tool", "kind": "pip", "decision": "adopt-fork",
                                                     "decided_at": "2026-10-05", "usage": "knowledge-rag"}])
            ledger.write_jsonl(ld / "runs.jsonl", [{"record": "tool", "round": 4, "step": "final-test",
                                                  "reviewer": "codex", "model": "gpt-6-astra", "effort": "medium",
                                                  "started_at": "2026-10-05T00:00:00Z", "ended_at": None,
                                                  "verdict": "not-approved", "commit": "abc1234", "thread_id": None}])
            fbase = {"record": "tool", "round": 4, "severity": "high", "category": "injection", "status": "open"}
            ledger.write_jsonl(ld / "findings" / "tool.jsonl", [
                {**fbase, "finding_id": "r04-1", "location": "src/a.py:3", "disclosure_id": "tool-01"},
                {**fbase, "finding_id": "r04-2", "location": "src/secret.py:9", "disclosure_id": "tool-K1"},
                {**fbase, "finding_id": "r04-3", "location": "src/b.py", "disclosure_id": None, "confidential": True},
                {**fbase, "finding_id": "r04-4", "location": "src/c.py", "disclosure_id": "tool-01",
                 "confidential": True}])

            p = build(now="2026-10-12T10:00:00Z")
            text = json.dumps(p)
            tabs = p["tabellen"]
            check("payload validates", validate(p) == [])
            check("payload leak-free", leak_errors(p) == [])
            check("no cleartext table without the switch", "sec_cleartext" not in tabs)
            for needle in ("SECRET-TITLE", "SECRET-REASON", "example.org", "acme/tool/issues", "advisories",
                           "tool-K1", "CVE-2026-12345", "GHSA-2345", "src/secret.py", "src/b.py", "someone"):
                check(f"never exported: {needle}", needle not in text)
            rv = tabs["sec_review"][0]
            check("latest verdict is the last verdict quote", _latest_verdict(
                "upstream as shipped: `VERDICT: DO NOT USE` (round 02); hardened copy: "
                "`FINAL TEST: APPROVED WITH CONDITIONS` (round 12, `b4da6b2`)") == "FINAL TEST: APPROVED WITH CONDITIONS"
                and _latest_verdict("`FINAL TEST: NOT APPROVED` - round 10 (`abe715b`)") == "FINAL TEST: NOT APPROVED"
                and _latest_verdict("`DO NOT USE` (Claude, round 02)") == "DO NOT USE"
                and _latest_verdict("in substance usable") is None)
            check("review from README + ledger", rv["name"] == "tool" and rv["version"] == "v1.2.3"
                  and rv["source"] == "https://github.com/acme/tool" and rv["fork"] is True
                  and rv["verdict"] == "not-approved" and rv["decision"] == "adopt-fork")
            dp = next(r for r in tabs["sec_disclosure"] if r["id"] == "tool-01")
            check("public disclosure complete", dp["record"] == "tool" and dp["answered_at"] == "2026-10-09"
                  and dp["due_by"] == "2026-10-14" and dp["published_at"] == "2026-10-07")
            check("how upstream closed it and our check are exported", dp["resolution"] == "fix-commit"
                  and dp["fix_release"] == "v1.2.4" and dp["closed_via_bot"] is True and dp["closed_at"] == "2026-10-11"
                  and dp["verification"] == "verified-fixed" and dp["verified_at"] == "2026-10-14")
            dc = next(r for r in tabs["sec_disclosure"] if r["id"] != "tool-01")
            check("unpublished disclosure pseudonymous", re.match(r"^c-[0-9a-f]{8}$", dc["id"])
                  and re.match(r"^confidential-[0-9a-f]{8}$", dc["record"]))
            check("unpublished disclosure: only allowed fields",
                  {k for k, v in dc.items() if v is not None} <= CONFIDENTIAL_DISCLOSURE_FIELDS)
            f2 = next(r for r in tabs["sec_finding"] if r["finding_id"] == "r04-2")
            f3 = next(r for r in tabs["sec_finding"] if r["finding_id"] == "r04-3")
            f1 = next(r for r in tabs["sec_finding"] if r["finding_id"] == "r04-1")
            check("finding of an unpublished disclosure hidden", f2["location"] is None and not f2["public"]
                  and f2["disclosure_id"] == dc["id"] and f2["record"] == dc["record"])
            check("confidential finding hidden", f3["location"] is None and not f3["public"])
            f4 = next(r for r in tabs["sec_finding"] if r["finding_id"] == "r04-4")
            check("confidential finding never names a published disclosure next to its placeholder",
                  f4["disclosure_id"] != "tool-01" and str(f4["disclosure_id"]).startswith("c-")
                  and f4["record"].startswith("confidential-") and f4["location"] is None)
            linked = {r["record"] for r in tabs["sec_finding"] + tabs["sec_disclosure"] + tabs["sec_run"]
                      + [{"record": x["name"]} for x in tabs["sec_review"]]
                      if r.get("record") and not r["record"].startswith("confidential-")}
            placeholders = {r["record"] for r in tabs["sec_finding"] + tabs["sec_disclosure"]
                            if r["record"].startswith("confidential-")}
            real_ids = {r["id"] for r in tabs["sec_disclosure"] if not r["id"].startswith("c-")}
            check("no row joins a placeholder to a real name or real disclosure id",
                  all(not (r["record"] in placeholders and (r.get("disclosure_id") in real_ids))
                      for r in tabs["sec_finding"]) and linked.isdisjoint(placeholders))
            check("published finding with location", f1["public"] and f1["location"] == "src/a.py:3")
            check("week counts", sum(r["count"] for r in tabs["sec_disclosure_week"]) == 2
                  and all(r["week"] == "2026-10-05" for r in tabs["sec_disclosure_week"]))
            check("placeholders stable", build(now="2026-10-12T10:00:00Z") == p)

            pc = build(cleartext=True, now="2026-10-12T10:00:00Z")
            ct = {r["placeholder"]: r for r in pc["tabellen"]["sec_cleartext"]}
            check("cleartext maps placeholders", ct.get(dc["id"], {}).get("real_id") == "tool-K1"
                  and ct[dc["id"]]["ghsa"] == "GHSA-2345-6789-cfgh" and ct[dc["id"]]["cve"] == "CVE-2026-12345"
                  and ct.get(dc["record"], {}).get("real_id") == "tool")
            check("cleartext never carries a location", "src/secret.py" not in json.dumps(pc))
            check("manifest says cleartext", pc["tabellen"]["manifest"][0]["cleartext"] is True)
            check("cleartext payload validates", validate(pc) == [])

            bad = json.loads(text)
            bad["tabellen"]["sec_disclosure"][0]["repo"] = "acme/tool"
            check("undeclared column refused", validate(bad) != [])
            bad = json.loads(text)
            bad["tabellen"]["sec_finding"][0]["location"] = "C:/Users/me/x.py"
            check("absolute location refused", validate(bad) != [])
            bad = json.loads(text)
            bad["tabellen"]["sec_finding"][0]["location"] = "/home/me/x.py"
            check("home location refused", validate(bad) != [])
            bad = json.loads(text)
            bad["tabellen"]["sec_run"][0]["model"] = "token=abcdefgh12345"
            check("credential pattern caught", leak_errors(bad) != [])
            bad = json.loads(text)
            bad["tabellen"]["sec_review"][0]["verdict_raw"] = "ask x.y@example.org"
            check("mail address caught", leak_errors(bad) != [])
            bad = json.loads(text)
            bad["tabellen"]["sec_review"][0]["verdict"] = "great"
            check("value list enforced", validate(bad) != [])

            ledger.write_jsonl(ld / "findings" / "tool.jsonl", [
                {**fbase, "finding_id": "r04-9", "location": "x.py", "disclosure_id": "nope-01"}])
            try:
                build()
                check("unknown disclosure id refused", False)
            except ExportError:
                check("unknown disclosure id refused", True)

            received = {}

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):  # noqa: N802
                    received["auth"] = self.headers.get("Authorization")
                    received["body"] = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"tabellen": {}}')

                def log_message(self, *args):
                    pass

            srv = HTTPServer(("127.0.0.1", 0), Handler)
            th = threading.Thread(target=srv.handle_request, daemon=True)
            th.start()
            saved_proxy = {k: os.environ.get(k) for k in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy")}
            for k in ("HTTP_PROXY", "http_proxy"):
                os.environ[k] = "http://127.0.0.1:9"        # a proxy that would swallow the token
            for k in ("NO_PROXY", "no_proxy"):
                os.environ.pop(k, None)
            try:
                os.environ["UJC_DASHBOARD_URL"] = f"http://127.0.0.1:{srv.server_port}/api/ingest/security"
                os.environ["UJC_DASHBOARD_TOKEN"] = "test-token-123"
                url, token = _target()
                rc = send(p, url, token)
            finally:
                for k, v in saved_proxy.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            th.join(5)
            srv.server_close()
            check("send posts with bearer token, proxy ignored", rc == 0
                  and received.get("auth") == "Bearer test-token-123"
                  and json.loads(received["body"])["plugin_version"] == PLUGIN_VERSION)

            hits = []

            class Redirect(BaseHTTPRequestHandler):
                def do_POST(self):  # noqa: N802
                    hits.append(self.path)
                    self.send_response(307)
                    self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                    self.end_headers()

                def log_message(self, *args):
                    pass

            srv = HTTPServer(("127.0.0.1", 0), Redirect)
            th = threading.Thread(target=srv.handle_request, daemon=True)
            th.start()
            rc = send(p, f"http://127.0.0.1:{srv.server_port}/api/ingest/security", "t", attempts=1)
            th.join(5)
            srv.server_close()
            check("redirect not followed", rc == 1 and hits == ["/api/ingest/security"])

            for host in ("10.1.2.3", "172.16.0.5", "172.31.255.1", "192.168.20.35", "127.0.0.1", "[::1]",
                         "[fd12:3456::1]", "dash", "dash.lan", "agentdash.local", "x.internal", "box.home.arpa"):
                check(f"http allowed: {host}", check_url(f"http://{host}:8001/api/ingest/security") is not None)
            for host in ("dash.example", "8.8.8.8", "169.254.1.1", "100.64.0.1", "0.0.0.1", "198.18.0.1",
                         "240.0.0.1", "172.32.0.1", "[fe80::1]", "[::ffff:192.168.1.1]", "[2002:c0a8:101::1]",
                         "[2001::1]", "[64:ff9b::c0a8:101]", "dash.lan.example.com"):
                check(f"http refused: {host}", _raises(lambda h=host: check_url(f"http://{h}/api/ingest/security")))
            check("https anywhere", check_url("https://dash.example/api/ingest/security"))
            check("allow_http_lan off", _raises(lambda: check_url("http://10.1.2.3/api", allow_http_lan=False)))
            check("cleartext never over LAN http", _raises(lambda: check_url("http://10.1.2.3/api", cleartext=True))
                  and _raises(lambda: check_url("http://dash.lan/api", cleartext=True)))
            check("cleartext over https or loopback", check_url("https://dash.lan/api", cleartext=True)
                  and check_url("http://127.0.0.1:8001/api", cleartext=True)
                  and check_url("http://[::1]:8001/api", cleartext=True))
            for bad in ("https://u:p@dash.example/api", "https://dash.example/api?x=1", "https://dash.example/api#f",
                        "ftp://dash.example/api"):
                check(f"url refused: {bad}", _raises(lambda b=bad: check_url(b)))
            os.environ["UJC_DASHBOARD_ALLOW_HTTP_LAN"] = "0"
            os.environ["UJC_DASHBOARD_URL"] = "http://10.1.2.3/api/ingest/security"
            check("switch off by environment", _raises(_target))
            os.environ.pop("UJC_DASHBOARD_ALLOW_HTTP_LAN", None)
            os.environ["UJC_DASHBOARD_URL"] = "http://dash.example/api/ingest/security"
            check("plain http to a public name refused", _raises(_target))
        finally:
            for n, v in saved.items():
                setattr(_common, n, v)
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    out(f"export_dashboard self-test: {ok}/{total} {'OK' if ok == total else 'FAILED'}")
    return 0 if ok == total else 1
# public-check: end-allow


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export the checker's metadata for a dashboard ingest")
    ap.add_argument("--out", default=None, help="file for the payload (default $UJC_DASHBOARD_OUT, else stdout)")
    ap.add_argument("--cleartext", action="store_true",
                    help="also deliver sec_cleartext (placeholder -> real name; LAN-only reader)")
    ap.add_argument("--send", action="store_true", help="POST the payload to the ingest")
    ap.add_argument("--summary", action="store_true", help="print the row counts only")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    try:
        errors, _counts = ledger.check_all()
        if errors:
            for e in errors:
                err(f"ERROR: ledger: {e}")
            return 1
        payload = build(cleartext=a.cleartext)
        problems = validate(payload) + leak_errors(payload)
        for p in problems:
            err(f"ERROR: {p}")
        if problems:
            err("ERROR: nothing exported")
            return 1
        counts = ", ".join(f"{t} {len(r)}" for t, r in payload["tabellen"].items())
        err(f"payload: {counts}{' (with cleartext)' if a.cleartext else ''}")
        if a.send:
            url, token = _target(cleartext=a.cleartext)
            return send(payload, url, token)
        if a.summary:
            return 0
        text = json.dumps(payload, ensure_ascii=True, indent=1)
        target = a.out or os.environ.get("UJC_DASHBOARD_OUT")
        if target:
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="ascii", newline="\n") as fh:
                fh.write(text + "\n")
            err(f"OK: written to {path.name}")
        else:
            sys.stdout.write(text + "\n")
        return 0
    except (ExportError, ledger.LedgerError) as exc:
        err(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
