#!/usr/bin/env python3
"""Maintain the register of upstream disclosures: check, generate the overview, add an
entry, publish after disclosure.

Stored per reviewed repository ("record", rule since 12.10.2026): everything about a reviewed
repository lives in its folders, the root folders hold only what belongs to the checker itself.

  private/records/<record>/disclosures/register.json  public disclosures (issues, comments,
                                                     published advisories after "publish");
                                                     local only since 06.11.2026
  private/repos/<record>/disclosures/register.json   confidential ones (submitted advisories,
                                                     mails, confidential issues/comments)
  disclosures/register.json, private/disclosures/register.json   the checker's own findings only
The tools read all of them and write every entry into the file of its record and part. The record
of an entry: field "record", else the folder of its draft (private/records/<record>/... or
private/repos/<record>/...), else the record whose README names the repository as "Upstream".
Overviews: private/records/<record>/disclosures/REGISTER.md + REGISTER_de.md (public) and
private/repos/<record>/disclosures/REGISTER.md (all); for the root README.md + README_de.md.

Per entry (list of objects):

    id                  internal, <repo-short>-NN
    repo                owner/name of the upstream
    finding             short title
    severity_class      critical | non-critical
    severity_reason     one sentence why
    channel             issue | advisory | email | comment
    reference           issue no. / GHSA ID / Message-ID / comment ID
    url                 link to the disclosure (empty for email)
    created             time of the disclosure (ISO, UTC)
    account             GitHub account or sender
    upstream_ref        checked upstream state (SHA or tag@SHA)
    draft               path of the draft (relative to the checker)
    status              open | answered | fix-pr | fixed | rejected | closed
    last_checked        time of the last watch run (ISO, UTC) or null
    notes               free text
    links               maintained by the watch: linked PRs/commits
    comments_seen       maintained by the watch

    record              folder name below repos/ (the reviewed repository); absent = root
    confidential        true = stays in the confidential part (comments on advisories,
                        GitLab confidential issues) until "publish"
    public              true after "publish" (advisories only)

    response_days       promised response time per the upstream policy (days from
    response_workdays   'created') or in working days, otherwise null - from the field
                        "policy" of the draft; disclosure_watch.py reports "deadline
                        passed without response" while the status is "open"
    deadline_reported   set by the watch: when the deadline was first reported
    policy_blob         blob SHA of the SECURITY.md that was checked against (null = none)

    Optional, for the dashboard export (tools/export_dashboard.py), set with "set":
    severity            critical | high | medium | low (finer than severity_class)
    category            fixed list, see _common.CATEGORIES
    cve, ghsa           identifiers once assigned (exported only after publishing)
    due_by              YYYY-MM-DD, overrides the deadline computed from response_days /
                        response_workdays (e.g. an agreed embargo date)
    embargo_until       YYYY-MM-DD, agreed end of the embargo
    published_at        YYYY-MM-DD, set by "publish"
    answered_at         YYYY-MM-DD, first status answered / fix-pr / rejected / closed
    fixed_at            YYYY-MM-DD, first status fixed (both stamped by "set --status" and
                        by the watch; never moved once set)

    How upstream dealt with it - filled by the watch, upstream's account (a claim):
    upstream_state      open | closed | triage | draft | published | withdrawn
    closed_at           YYYY-MM-DD the issue was closed
    resolution          fix-merged-pr | fix-commit | pr-open | wontfix | duplicate |
                        closed-no-fix-ref | advisory-published | advisory-closed
    fix_commit          SHA of the fix; fix_release: first release tag containing it
    closed_via_bot      the closing comment carries a bot signature
    What we found in the fixed code - set by a human ("set --verification"):
    verification        verified-fixed | partial | not-fixed | unverified (stamps verified_at);
                        status "fixed" is only accepted with verified-fixed

    python tools/disclosures/register.py check
    python tools/disclosures/register.py readme
    python tools/disclosures/register.py publish <id> [--reason "..."]
        Advisory: only if GitHub reports state=published; mail: with a reason
        (fix release + disclosure). Marks the state only (public, published_at); the draft
        stays below private/ - nothing is copied into the versioned tree.
    python tools/disclosures/register.py --self-test
    python tools/disclosures/register.py new --repo o/r --short omc --finding "..." \
        --severity-class non-critical --reason "..." --channel issue --reference 123 \
        --url https://... --created 2026-10-10T15:15:17Z --account ujconsulting \
        --upstream-ref <sha> --draft private/repos/<name>/disclosures/<file>.md \
        [--response-days N | --response-workdays N] [--policy-blob <sha>] \
        [--id <id>] [--confidential] [--record <name>]
    python tools/disclosures/register.py set <id> [--status S] [--severity S] [--category C]
        [--cve CVE-...] [--ghsa GHSA-...] [--due-by YYYY-MM-DD] [--embargo-until YYYY-MM-DD]
        [--verification verified-fixed|partial|not-fixed|unverified] [--fix-commit SHA]
        [--fix-release TAG]
        Sets the optional fields; an empty value removes one. A status change stamps
        answered_at / fixed_at, a verification verified_at (today, or --on YYYY-MM-DD).
    python tools/disclosures/register.py migrate --record <name> [--dry-run]
        Moves the entries of a reviewed repository out of the root registers into its record
        (field "record" set; draft folder or "Upstream" row decides which entries belong to it).
    python tools/disclosures/register.py posted <draft.md> --url <link> [--reference R]
        [--created ISO] [--account A]
        A disclosure that had to be posted BY HAND (e.g. a comment on a GitHub security advisory -
        there is no REST API for it): the same checks as a submit tool (fields, leak scan, policy,
        Codex gates, hash-bound approval for the draft's channel), the link must be https and
        point into the repository; reference from the link (issue number, comment fragment;
        with field "advisory": "<GHSA>#<fragment>"); a draft under private/ makes the entry
        confidential. The entry gets the draft's ID; the approval is consumed.

Exit 0 ok, 1 register invalid, 2 operator error.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import shutil  # noqa: E402

import _common  # noqa: E402  - store locations are read at run time (_common.REGISTER ...)
from _common import (CATEGORIES, CHANNELS, CVE_RE, DATE_FIELDS, GHSA_RE,  # noqa: E402
                     PRIVATE_DISCLOSURES, PRIVATE_REPOS, RESOLUTIONS, SEVERITIES, UPSTREAM_STATES,
                     VERIFICATIONS, stamp_status,
                     ROOT, SEVERITY_CLASSES, STATUS_VALUES, DisclosureError, check_record, check_repo, err,
                     gh_get, is_public, is_under_private, load_register, next_id, now_iso, out,
                     record_dirs, record_of, records_enabled, save_register, write_text)

REQUIRED = ("id", "repo", "finding", "severity_class", "severity_reason", "channel",
            "reference", "url", "created", "upstream_ref", "status", "last_checked",
            "notes")


def _is_date(value) -> bool:
    from datetime import date
    try:
        return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", str(value))) and date.fromisoformat(str(value)) is not None
    except ValueError:
        return False


SET_FIELDS = ("severity", "category", "cve", "ghsa", "due_by", "embargo_until", "verification",
              "fix_commit", "fix_release")


def set_fields(entries, disclosure_id, values: dict, status=None, on=None):
    """Sets the optional dashboard fields of one entry ('' removes a field) and, with a status,
    stamps answered_at / fixed_at. Validates the result before anything is saved."""
    e = next((x for x in entries if x.get("id") == disclosure_id), None)
    if e is None:
        raise DisclosureError(f"{disclosure_id} not in the register")
    if on is not None and not _is_date(on):
        raise DisclosureError("--on must be YYYY-MM-DD")
    for k, v in values.items():
        if v is None:
            continue
        if v == "":
            e.pop(k, None)
        else:
            if k == "verification" and v != e.get("verification"):
                e["verified_at"] = (on or now_iso())[:10]
            e[k] = v
    if status is not None:
        if status not in STATUS_VALUES:
            raise DisclosureError(f"status {status!r} not in {'/'.join(STATUS_VALUES)}")
        if status != e.get("status"):
            stamp_status(e, status, on)
    errors = check([e])
    if errors:
        raise DisclosureError("; ".join(errors))
    return e


def check(entries):
    errors = []
    ids = set()
    for i, e in enumerate(entries):
        who = e.get("id", f"#{i}")
        if e.get("record"):
            try:
                check_record(e["record"])
            except DisclosureError as exc:
                errors.append(f"{who}: {exc}")
        if "confidential" in e and not isinstance(e["confidential"], bool):
            errors.append(f"{who}: confidential must be true or false")
        for k in REQUIRED:
            if k not in e:
                errors.append(f"{who}: field {k} missing")
        if e.get("id") in ids:
            errors.append(f"{who}: duplicate id")
        ids.add(e.get("id"))
        if e.get("severity_class") not in SEVERITY_CLASSES:
            errors.append(f"{who}: severity_class {e.get('severity_class')!r}")
        if e.get("channel") not in CHANNELS:
            errors.append(f"{who}: channel {e.get('channel')!r}")
        if e.get("status") not in STATUS_VALUES:
            errors.append(f"{who}: status {e.get('status')!r}")
        if e.get("severity") not in (None,) + SEVERITIES:
            errors.append(f"{who}: severity {e.get('severity')!r}")
        if e.get("category") not in (None,) + CATEGORIES:
            errors.append(f"{who}: category {e.get('category')!r}")
        if e.get("cve") is not None and not CVE_RE.match(str(e["cve"])):
            errors.append(f"{who}: cve {e.get('cve')!r}")
        if e.get("ghsa") is not None and not GHSA_RE.match(str(e["ghsa"])):
            errors.append(f"{who}: ghsa {e.get('ghsa')!r}")
        for k in DATE_FIELDS:
            if e.get(k) is not None and not _is_date(e[k]):
                errors.append(f"{who}: {k} must be YYYY-MM-DD")
        for k, allowed in (("upstream_state", UPSTREAM_STATES), ("resolution", RESOLUTIONS),
                           ("verification", VERIFICATIONS)):
            if e.get(k) not in (None,) + allowed:
                errors.append(f"{who}: {k} {e.get(k)!r}")
        if e.get("fix_commit") is not None and not re.match(r"^[0-9a-f]{7,40}$", str(e["fix_commit"])):
            errors.append(f"{who}: fix_commit must be a hex SHA")
        if e.get("fix_release") is not None and not re.match(r"^[A-Za-z0-9._+-]{1,64}$", str(e["fix_release"])):
            errors.append(f"{who}: fix_release must be a tag name")
        if "closed_via_bot" in e and not isinstance(e["closed_via_bot"], bool):
            errors.append(f"{who}: closed_via_bot must be true or false")
        if e.get("status") == "fixed" and e.get("verification") != "verified-fixed":
            errors.append(f"{who}: status fixed needs verification verified-fixed (read the fixed code first)")
        try:
            if e.get("forge") in (None, "", "github"):
                check_repo(e.get("repo", ""))
            else:
                from forge import get_forge
                get_forge(e["forge"]).check_repo(e.get("repo", ""))
        except DisclosureError as exc:
            errors.append(f"{who}: {exc}")
    return errors


def _cell(text) -> str:
    return str(text if text not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


# Fixed texts of the generated overview; the German one is README_de.md next to it.
# Entry data (finding, reason, notes) stay in the language of the register (English).
README_TEXTS = {
    "en": {
        "lang": "[English]({en}) | [Deutsch]({de})",
        "title": "# Upstream disclosures - register",
        "title_record": "# Disclosures to {repo} - register",
        "title_own": "# Disclosures of the ujc-security-checker itself - register",
        "elsewhere": "Disclosures about reviewed repositories stay local with each record "
                     "(not versioned): `private/records/<name>/disclosures/REGISTER.md`.",
        "generated": "Generated from [`register.json`](register.json) with "
                     "`python tools/disclosures/register.py readme` - do not edit by hand.",
        "process": "Process and rules: skill [`finding-disclosure`]({up}.claude/skills/finding-disclosure/SKILL.md); "
                   "watch: `python tools/disclosures/disclosure_watch.py`, reports stay local "
                   "under `private/`.",
        "status": "Status meaning: `fix-pr` = a PR/commit refers to it (a claim, "
                  "not verified); only a human sets `fixed` after checking the merged code; "
                  "`closed` = closed upstream, reason see note.",
        "header": "| ID | Repo | Finding | Severity class | Channel | Reference | Created | Status | Last checked |",
        "reasons": "## Reason for the severity class and notes",
        "note": "Note", "link": "Link",
        "confidential": "Plus {n} confidential disclosure(s) (embargo, not in this repository).",
    },
    # public-check: begin-allow german  (the German overview README_de.md)
    "de": {
        "lang": "[English]({en}) | [Deutsch]({de})",
        "title": "# Meldungen an Upstream - Register",
        "title_record": "# Meldungen an {repo} - Register",
        "title_own": "# Meldungen des ujc-security-checker selbst - Register",
        "elsewhere": "Meldungen zu geprüften Repositories bleiben lokal bei der jeweiligen Akte "
                     "(nicht versioniert): `private/records/<name>/disclosures/REGISTER.md`.",
        "generated": "Erzeugt aus [`register.json`](register.json) mit "
                     "`python tools/disclosures/register.py readme` - nicht von Hand bearbeiten. "
                     "Die Einträge stehen in der Sprache des Registers (Englisch).",
        "process": "Ablauf und Regeln: Skill [`finding-disclosure`]({up}.claude/skills/finding-disclosure/README_de.md); "
                   "Beobachtung: `python tools/disclosures/disclosure_watch.py`, Berichte bleiben lokal "
                   "unter `private/`.",
        "status": "Bedeutung des Status: `fix-pr` = ein PR/Commit bezieht sich darauf (eine Behauptung, "
                  "nicht geprüft); `fixed` setzt nur ein Mensch nach Lesen des gemergten Codes; "
                  "`closed` = upstream geschlossen, Grund siehe Notiz.",
        "header": "| ID | Repo | Befund | Schwereklasse | Kanal | Referenz | Gemeldet | Status | Zuletzt geprüft |",
        "reasons": "## Begründung der Schwereklasse und Notizen",
        "note": "Notiz", "link": "Verweis",
        "confidential": "Dazu {n} vertrauliche Meldung(en) (Embargo, nicht in diesem Repository).",
    },
    # public-check: end-allow
}


def readme_text(entries, lang: str = "en", title: str = None, up: str = "../") -> str:
    t = README_TEXTS[lang]
    lines = [
        title or t["title"],
        "",
        t["generated"],
        t["process"].format(up=up),
        "",
        t["status"],
        "",
        t["header"],
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for e in entries:
        ref = e.get("reference", "")
        if e.get("url"):
            ref = f"[{ref}]({e['url']})"
        lines.append("| " + " | ".join(_cell(x) for x in (
            e.get("id"), e.get("repo"), e.get("finding"), e.get("severity_class"), e.get("channel"),
            ref, (e.get("created") or "")[:16].replace("T", " "), e.get("status"),
            (e.get("last_checked") or "")[:16].replace("T", " "))) + " |")
    lines += ["", t["reasons"], ""]
    for e in entries:
        lines.append(f"- **{e.get('id')}** ({e.get('severity_class')}): "
                     f"{e.get('severity_reason') or '-'}"
                     + (f" - {t['note']}: {e['notes']}" if e.get("notes") else ""))
        for b in e.get("links") or []:
            lines.append(f"  - {t['link']}: {b.get('kind')} {b.get('number') or b.get('sha', '')[:12]} "
                         f"{b.get('state', '')} {b.get('url', '')}".rstrip())
    return "\n".join(lines)


def public_readme(entries, confidential: int, lang: str, names=("README.md", "README_de.md"),
                  title: str = None, up: str = "../", extra: str = "") -> str:
    t = README_TEXTS[lang]
    text = t["lang"].format(en=names[0], de=names[1]) + "\n\n" + readme_text(entries, lang, title, up)
    if confidential:
        text += "\n\n" + t["confidential"].format(n=confidential)
    if extra:
        text += "\n\n" + extra
    return text


def _write_pair(folder: Path, names, entries, confidential, title_key, repo, up, extra_key=None):
    """English overview + German one with the source hash (tools/public_check.py pairing)."""
    en, de = names
    texts = {lang: public_readme(entries, confidential, lang, names,
                                 README_TEXTS[lang][title_key].format(repo=repo), up,
                                 README_TEXTS[lang][extra_key] if extra_key else "")
             for lang in ("en", "de")}
    write_text(folder / en, texts["en"])
    digest = hashlib.sha256((folder / en).read_bytes()).hexdigest()
    write_text(folder / de, f"<!-- source: {en} sha256:{digest} -->\n" + texts["de"])


def write_readme(entries=None) -> None:
    """Overviews per store, locations read at run time from the current register files (a
    self-test that moves the register therefore never touches the real overviews):
    root (the checker's own disclosures): disclosures/README.md + README_de.md and
    private/disclosures/README.md; per record: private/records/<r>/disclosures/REGISTER.md + REGISTER_de.md
    (public entries) and private/repos/<r>/disclosures/REGISTER.md (all)."""
    entries = load_register() if entries is None else entries
    by_record = {}
    for e in entries:
        by_record.setdefault(e.get("record") or "", []).append(e)
    by_record.setdefault("", [])
    if records_enabled():
        for f in sorted((_common._base(_common.REGISTER_PRIVATE) / "records").glob("*/disclosures/REGISTER.md")):
            by_record.setdefault(f.parent.parent.name, [])     # refresh an overview that became empty
    for record, items in sorted(by_record.items()):
        public = [e for e in items if is_public(e)]
        confidential = len(items) - len(public)
        pub_dir, priv_dir = record_dirs(record)
        if not record:
            _write_pair(pub_dir, ("README.md", "README_de.md"), public, confidential, "title_own", "",
                        "../", "elsewhere")
            private_file = priv_dir / "README.md"
        else:
            # A record's public overview never mentions confidential entries - not even their
            # number: per repository that alone would reveal a disclosure under embargo. Without
            # public entries there is no public overview at all.
            repo = next((e.get("repo") for e in items if e.get("repo")), record)
            if public:
                _write_pair(pub_dir, ("REGISTER.md", "REGISTER_de.md"), public, 0, "title_record",
                            repo, "../../../../")
            else:
                for name in ("REGISTER.md", "REGISTER_de.md"):
                    if (pub_dir / name).exists():
                        (pub_dir / name).unlink()
            private_file = priv_dir / "REGISTER.md"
        if confidential or private_file.exists():
            write_text(private_file, "> CONFIDENTIAL - all disclosures including embargo.\n\n"
                       + readme_text(items, "en", README_TEXTS["en"]["title_own" if not record else "title_record"]
                                     .format(repo=record), "../../" if not record else "../../../../"))


def publish(entries, disclosure_id, reason, source=None):
    """After disclosure: mark the entry public (state only). Nothing is copied or moved: since
    06.11.2026 no draft or report is versioned (repos/<name>/ holds only the summary README),
    so the draft stays where it is, below private/. Advisories only if GitHub reports
    state=published."""
    e = next((x for x in entries if x.get("id") == disclosure_id), None)
    if e is None:
        raise DisclosureError(f"{disclosure_id} not in the register")
    if is_public(e):
        raise DisclosureError(f"{disclosure_id} is already public")
    if e.get("channel") == "advisory":
        if source is None and e.get("forge") not in (None, "", "github"):
            from forge import get_forge
            source = get_forge(e["forge"]).get
        fetch = source or gh_get
        a = fetch(f"repos/{e['repo']}/security-advisories/{e['reference']}")
        if (a or {}).get("state") != "published":
            raise DisclosureError(f"advisory {e['reference']} is not published "
                                  f"(state={(a or {}).get('state')}) - the embargo still applies")
    elif not reason:
        raise DisclosureError("for mail and confidential-issue disclosures give --reason "
                              "(fix release + disclosure)")
    e["public"] = True
    e.setdefault("published_at", now_iso()[:10])
    e["notes"] = (e.get("notes", "") + f" Published {now_iso()[:10]}: {reason or 'advisory published'}.").strip()
    if e.get("channel") == "email":
        # Mails stay confidential as a channel; only the draft moves.
        e["public"] = False
    return e


def migrate(entries, record: str, dry_run: bool = False) -> int:
    """Sets field 'record' on the entries that belong to <record> and are still in the root
    registers; saving moves them into the record's files. Nothing else changes."""
    check_record(record)
    if not records_enabled():
        raise DisclosureError("records are switched off (register not in the usual layout)")
    if not ((_common._base(_common.REGISTER) / "repos" / record).is_dir()
            or (_common._base(_common.REGISTER_PRIVATE) / "records" / record).is_dir()):
        raise DisclosureError(f"neither repos/{record}/ nor private/records/{record}/ exists - no such record")
    moving = [e for e in entries if not e.get("record") and record_of(e) == record]
    for e in moving:
        out(f"  {e.get('id')}: {e.get('channel')} -> repos/{record}/ "
            f"({'public' if is_public(e) else 'confidential'})")
    ids = {e.get("id") for e in entries if e.get("record") == record or e in moving}
    files = _root_files_of(ids)
    for src, sub_dir in files:
        out(f"  file {_common._shown(src)} -> {_common._shown(record_dirs(record)[1] / sub_dir / src.name)}")
    if dry_run or not (moving or files):
        out(f"{'DRY RUN: ' if dry_run else ''}{len(moving)} entries, {len(files)} files for record {record}")
        return 0
    for e in moving:
        e["record"] = record
    if moving:
        save_register(entries)
        write_readme(entries)
    _move_files(files, record)
    out(f"OK: {len(moving)} entries and {len(files)} files moved to record {record}")
    return 0


def _root_files_of(ids):
    """(source, sub folder) of the approvals and Codex check files of these IDs that still lie
    in the root (private/disclosures/approvals/, private/disclosures/checks/)."""
    res = []
    for sub_dir, root_dir in (("approvals", _common.APPROVALS), ("checks", _common.CHECKS)):
        if not root_dir.is_dir():
            continue
        for f in sorted(root_dir.iterdir()):
            if f.is_file() and any(f.name == i or f.name.startswith(f"{i}.") or f.name.startswith(f"{i}-")
                                   for i in ids if i):
                res.append((f, sub_dir))
    return res


def _move_files(files, record):
    """Moves them into the record's confidential folder; check records get their output= path
    rewritten (the output bytes and their hash stay as they are)."""
    priv = record_dirs(record)[1]
    moved = {}
    for src, sub_dir in files:
        dst = priv / sub_dir / src.name
        if dst.exists():
            raise DisclosureError(f"{_common._shown(dst)} exists already - not moving {src.name}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        moved[_common._shown(src)] = _common._shown(dst)
    for dst in [priv / "checks" / src.name for src, sub_dir in files if sub_dir == "checks" and src.suffix == ".check"]:
        lines = dst.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line.startswith("output=") and line[len("output="):] in moved:
                lines[i] = "output=" + moved[line[len("output="):]]
        write_text(dst, "\n".join(lines))


def _reference_from_url(meta, url: str) -> str:
    from urllib.parse import urlsplit
    u = urlsplit(url)
    frag = u.fragment
    if meta.get("advisory"):
        return f"{meta['advisory']}#{frag}" if frag else str(meta["advisory"])
    m = re.search(r"/(?:issues|pull|-/issues|-/merge_requests)/(\d+)", u.path)
    if m:
        return f"{m.group(1)}#{frag}" if frag and meta.get("channel") == "comment" else m.group(1)
    return frag or u.path.rsplit("/", 1)[-1]


def posted(draft: Path, url: str, reference: str = "", created: str = "", account: str = "") -> int:
    """Register a disclosure that was posted by hand, after the same gates as a submit tool."""
    import _submit
    from forge import forge_of
    from urllib.parse import urlsplit
    try:
        meta, text, raw = _submit.prepare(draft, CHANNELS)
    except _common.AlreadySubmitted as exc:
        return _submit.already_submitted_exit(exc, True)
    f = forge_of(meta)
    u, web = urlsplit(url), urlsplit(f.web)
    if u.scheme != "https" or u.netloc.lower() != web.netloc.lower() \
            or not (u.path + "/").startswith(f"{web.path.rstrip('/')}/{meta['repo']}/"):
        raise DisclosureError(f"--url must be an https link into {f.web}/{meta['repo']}/ (got {url!r})")
    public_channel = meta["channel"] in ("issue", "comment") and not is_under_private(draft)
    if not _submit.leak_check(meta, meta.get("title", ""), text,
                              block_exploit=meta["severity_class"] == "critical" and public_channel):
        out("ERROR: leak scan - not registered")
        return 1
    try:
        _submit.policy_or_abort(meta, text)
        _submit.approval_or_abort(meta, raw, meta["channel"])
    except DisclosureError as exc:          # policy, Codex gates or no valid approval
        err(f"ERROR: {exc}")
        return 1
    if is_under_private(draft):
        meta = {**meta, "confidential": True}
    entry = _submit.register_entry(meta, draft, meta["channel"], reference or _reference_from_url(meta, url),
                                   url, created or now_iso(), account, meta.get("note", "posted by hand"))
    out(f"OK: {entry['id']} registered ({'confidential' if not is_public(entry) else 'public'}, "
        f"record {entry.get('record') or '-'}): {url}")
    return 0


def self_test() -> int:
    import tempfile

    import _common

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    g = globals()
    saved = (g["ROOT"], g["PRIVATE_DISCLOSURES"], g["PRIVATE_REPOS"], _common.PRIVATE)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        g["ROOT"], g["PRIVATE_DISCLOSURES"], g["PRIVATE_REPOS"] = (
            root, root / "private" / "disclosures", root / "private" / "repos")
        _common.PRIVATE = root / "private"
        try:
            for d in ("private/disclosures", "private/repos/x/disclosures", "private/other", "outside"):
                (root / d).mkdir(parents=True)
            (root / "private/disclosures/a.md").write_text("a\n", encoding="utf-8")
            (root / "private/repos/x/disclosures/b.md").write_text("b\n", encoding="utf-8")
            (root / "private/other/c.md").write_text("c\n", encoding="utf-8")
            (root / "private/disclosures/d.txt").write_text("d\n", encoding="utf-8")
            (root / "private/disclosures/dir.md").mkdir()
            (root / "outside/e.md").write_text("e\n", encoding="utf-8")
            entries = [{"id": "t-01", "channel": "email", "repo": "a/b", "notes": "",
                        "draft": "private/other/c.md"}]
            entries[0]["draft"] = "private/disclosures/a.md"
            publish(entries, "t-01", "fix release")
            check("publish marks the state and moves nothing",
                  (root / "private/disclosures/a.md").exists() and not (root / "disclosures/a.md").exists()
                  and entries[0]["draft"] == "private/disclosures/a.md" and "published_at" in entries[0])
        finally:
            g["ROOT"], g["PRIVATE_DISCLOSURES"], g["PRIVATE_REPOS"], _common.PRIVATE = saved
    # optional dashboard fields and the status stamps (in memory, nothing saved)
    base_e = {"id": "s-01", "repo": "acme/tool", "finding": "f", "severity_class": "critical",
              "severity_reason": "r", "channel": "advisory", "reference": "GHSA-aaaa-bbbb-cccc",
              "url": "", "created": "2026-10-10T00:00:00Z", "upstream_ref": "main@x", "status": "open",
              "last_checked": None, "notes": ""}
    ents = [dict(base_e)]
    set_fields(ents, "s-01", {"severity": "high", "category": "injection",
                              "ghsa": "GHSA-2345-6789-cfgh"},  # public-check: allow embargo  (invented id)
               "answered", "2026-10-11")
    check("set fields", ents[0]["severity"] == "high" and ents[0]["answered_at"] == "2026-10-11"
          and "fixed_at" not in ents[0])
    set_fields(ents, "s-01", {"verification": "verified-fixed"}, "fixed", "2026-10-15")
    check("fixed stamps fixed_at, keeps answered_at", ents[0]["fixed_at"] == "2026-10-15"
          and ents[0]["answered_at"] == "2026-10-11")
    set_fields(ents, "s-01", {"category": ""})
    check("empty value removes a field", "category" not in ents[0])
    for bad in ({"severity": "huge"}, {"category": "rce"}, {"cve": "CVE-26-1"}, {"due_by": "12.10.2026"},
                {"ghsa": "GHSA-0000-0000-0000"}):
        check(f"set refuses {bad}", _raises(lambda b=bad: set_fields([dict(base_e)], "s-01", b)))
    check("check refuses a bad date", globals()["check"]([{**base_e, "embargo_until": "2026-13-01"}]) != [])
    check("fixed without verification refused",
          _raises(lambda: set_fields([dict(base_e)], "s-01", {}, "fixed", "2026-10-15")))
    ents = [dict(base_e)]
    set_fields(ents, "s-01", {"verification": "verified-fixed", "fix_commit": "c3d537a",
                              "fix_release": "v0.9.88"}, "fixed", "2026-10-15")
    check("verified fix accepted and stamped", ents[0]["status"] == "fixed"
          and ents[0]["verified_at"] == "2026-10-15" and ents[0]["fix_release"] == "v0.9.88")
    for bad in ({"verification": "maybe"}, {"fix_commit": "zz"}, {"fix_release": "a b"}):
        check(f"set refuses {bad}", _raises(lambda b=bad: set_fields([dict(base_e)], "s-01", b)))
    check("check refuses an unknown resolution",
          globals()["check"]([{**base_e, "resolution": "fixed-somehow"}]) != [])
    ok_s, total_s = _self_test_store()
    ok, total = ok + ok_s, total + total_s
    out(f"register self-test: {ok}/{total} OK")
    return 0 if ok == total else 1


def _self_test_store():
    """Storage per record in a temporary checker tree: B1 (a moved register never touches the
    real overviews), save/load per record, migrate, new, posted, record_or_abort, watch split."""
    import json
    import tempfile

    import _submit
    import approval as approval_mod
    import disclosure_watch as dw

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    real_readme = _common.REGISTER.parent / "README.md"
    real_before = real_readme.read_bytes() if real_readme.exists() else None
    names = ("ROOT", "PRIVATE", "REGISTER", "REGISTER_PRIVATE", "APPROVALS", "CHECKS", "ENV_FILE",
             "WATCH_CONFIG", "WATCH_CONFIG_LOCAL")
    saved = {n: getattr(_common, n) for n in names}
    saved_mod = (globals()["ROOT"], _submit.ROOT, _submit.FETCH_BLOB)
    switches = ("disclosure_codex_check", "claudex_finding_check", "claudex_exposure_check")
    saved_env = {k: os.environ.get(k) for k in switches}
    for k in switches:
        os.environ[k] = "off"
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        _common.ROOT = globals()["ROOT"] = _submit.ROOT = root
        _common.PRIVATE = root / "private"
        _common.REGISTER = root / "disclosures" / "register.json"
        _common.REGISTER_PRIVATE = root / "private" / "disclosures" / "register.json"
        _common.APPROVALS = root / "private" / "disclosures" / "approvals"
        _common.CHECKS = root / "private" / "disclosures" / "checks"
        _common.ENV_FILE = root / ".env"
        _common.WATCH_CONFIG = root / "disclosures" / "watch_config.json"
        _common.WATCH_CONFIG_LOCAL = root / "private" / "disclosures" / "watch_config.local.json"
        _submit.FETCH_BLOB = lambda repo, path: None
        try:
            for d in ("private/records/tool/disclosures", "private/repos/tool/disclosures", "disclosures",
                      "private/disclosures"):
                (root / d).mkdir(parents=True, exist_ok=True)
            write_text(root / "repos/tool/README.md", "| Upstream | `acme/tool` |\n")
            write_text(_common.WATCH_CONFIG, json.dumps({"own_repos": ["me/own"]}))
            check("records on in the usual layout", _common.records_enabled())
            check("record from the Upstream row", _common.record_of({"repo": "acme/tool"}) == "tool")
            check("record from the draft folder",
                  _common.record_of({"repo": "x/y"}, root / "private/repos/tool/disclosures/a.md") == "tool")
            check("no record for an unknown repository", _common.record_of({"repo": "x/y"}) == "")
            base = {"finding": "f", "severity_class": "non-critical", "severity_reason": "r",
                    "reference": "1", "url": "", "created": "2026-10-12T00:00:00Z", "upstream_ref": "main@x",
                    "status": "open", "last_checked": None, "notes": ""}
            entries = [{**base, "id": "tool-01", "repo": "acme/tool", "channel": "issue", "record": "tool"},
                       {**base, "id": "tool-02", "repo": "acme/tool", "channel": "advisory", "record": "tool"},
                       {**base, "id": "own-01", "repo": "me/own", "channel": "issue"},
                       {**base, "id": "tool-03", "repo": "acme/tool", "channel": "comment", "confidential": True,
                        "record": "tool"}]
            _common.save_register(entries)
            write_readme(entries)
            pub = _common.load_json(root / "private/records/tool/disclosures/register.json", [])
            priv = _common.load_json(root / "private/repos/tool/disclosures/register.json", [])
            check("public entry of a record in its public file", [e["id"] for e in pub] == ["tool-01"])
            check("advisory and confidential comment in the record's confidential file",
                  sorted(e["id"] for e in priv) == ["tool-02", "tool-03"])
            check("root holds only the checker's own entry",
                  [e["id"] for e in _common.load_json(_common.REGISTER, [])] == ["own-01"]
                  and not _common.load_json(_common.REGISTER_PRIVATE, []))
            check("load_register reads all stores", sorted(e["id"] for e in _common.load_register())
                  == ["own-01", "tool-01", "tool-02", "tool-03"])
            check("overviews per record: public pair and confidential one",
                  (root / "private/records/tool/disclosures/REGISTER.md").exists()
                  and (root / "private/records/tool/disclosures/REGISTER_de.md").read_text(encoding="utf-8")
                  .startswith("<!-- source: REGISTER.md sha256:")
                  and "tool-02" not in (root / "private/records/tool/disclosures/REGISTER.md").read_text(encoding="utf-8")
                  and "tool-02" in (root / "private/repos/tool/disclosures/REGISTER.md").read_text(encoding="utf-8"))
            reg_pub = (root / "private/records/tool/disclosures/REGISTER.md").read_text(encoding="utf-8") \
                + (root / "private/records/tool/disclosures/REGISTER_de.md").read_text(encoding="utf-8")
            check("embargo: a record's public overview never mentions confidential entries",
                  "confidential" not in reg_pub.lower() and "vertraulich" not in reg_pub.lower())
            (root / "private/records/secret/disclosures").mkdir(parents=True)
            only_conf = [{**base, "id": "secret-01", "repo": "acme/secret", "channel": "advisory",
                          "record": "secret"}]
            write_text(root / "private/records/secret/disclosures/REGISTER.md", "old generated overview")
            write_readme(entries + only_conf)
            check("embargo: no public overview for a record with only confidential entries",
                  not (root / "private/records/secret/disclosures/REGISTER.md").exists()
                  and not (root / "private/records/secret/disclosures/REGISTER_de.md").exists()
                  and (root / "private/repos/secret/disclosures/REGISTER.md").exists())
            res_c = {"time": "2026-10-12T09:00:00Z", "entries": [
                        {"id": "secret-01", "channel": "advisory", "repo": "acme/secret", "new_comments": [],
                         "links": [], "new_links": [], "newly_changed": True},
                        {"id": "tool-01", "channel": "issue", "repo": "acme/tool", "new_comments": [], "links": [],
                         "new_links": []},
                        {"id": "tool-02", "channel": "advisory", "repo": "acme/tool", "new_comments": [],
                         "links": [], "new_links": [], "newly_changed": True}],
                     "repos": [], "own_repos": [], "errors": [], "status_changes": [], "deadlines": []}
            for e in res_c["entries"]:
                e.update(public=e["channel"] == "issue", reference="1", url="", finding="f", state="open",
                         status_suggestion=None)
            written = [p.relative_to(root).as_posix() for p in dw.write_reports(res_c, entries + only_conf)]
            check("embargo: no public report for a record with only confidential entries",
                  not any(w.startswith("private/records/secret/") for w in written)
                  and any(w.startswith("private/repos/secret/disclosures/reports/") for w in written))
            pub_report = next((root / w for w in written if w.startswith("private/records/tool/")), None)
            check("embargo: a record's public report does not say that something was left out",
                  pub_report is not None and "confidential" not in pub_report.read_text(encoding="utf-8").lower()
                  and "tool-02" not in pub_report.read_text(encoding="utf-8"))
            check("root overview names only the own entry",
                  "own-01" in (root / "disclosures/README.md").read_text(encoding="utf-8")
                  and "tool-01" not in (root / "disclosures/README.md").read_text(encoding="utf-8"))
            # migrate: a legacy root entry (no record) whose draft lies in the record's folder
            legacy = {**base, "id": "tool-04", "repo": "acme/tool", "channel": "issue",
                      "draft": "private/records/tool/disclosures/04.md"}
            write_text(_common.REGISTER, json.dumps(_common.load_json(_common.REGISTER, []) + [legacy]))
            all_e = _common.load_register()
            check("migrate dry run changes nothing", migrate(all_e, "tool", True) == 0
                  and "tool-04" in [e["id"] for e in _common.load_json(_common.REGISTER, [])])
            write_text(_common.CHECKS / "tool-04-abc123.out.md", "| 1 | x |\n\nCHECK: CONFIRMED")
            write_text(_common.CHECKS / "tool-04.check",
                       "sha256=0\noutput=private/disclosures/checks/tool-04-abc123.out.md\noutput_sha256=1")
            write_text(_common.APPROVALS / "tool-04.approval", "action=issue\nsha256=0")
            write_text(_common.CHECKS / "tool-040.check", "other id, must stay")
            check("migrate moves the legacy entry", migrate(_common.load_register(), "tool") == 0
                  and "tool-04" in [e["id"] for e in _common.load_json(root / "private/records/tool/disclosures/register.json", [])]
                  and "tool-04" not in [e["id"] for e in _common.load_json(_common.REGISTER, [])])
            moved_check = root / "private/repos/tool/disclosures/checks/tool-04.check"
            check("migrate moves the checks and approvals of the entry, output= rewritten",
                  moved_check.exists() and "output=private/repos/tool/disclosures/checks/tool-04-abc123.out.md"
                  in moved_check.read_text(encoding="utf-8")
                  and (root / "private/repos/tool/disclosures/checks/tool-04-abc123.out.md").exists()
                  and (root / "private/repos/tool/disclosures/approvals/tool-04.approval").exists()
                  and not (_common.CHECKS / "tool-04.check").exists()
                  and (_common.CHECKS / "tool-040.check").exists())
            check("check record still found by ID after the move",
                  _common.check_path("tool-04") == moved_check)
            check("migrate of an unknown record refused",
                  _raises(lambda: migrate(_common.load_register(), "nope")))
            # new --id --confidential --record
            rc = main(["new", "--repo", "acme/tool", "--short", "tool", "--finding", "f", "--severity-class",
                       "non-critical", "--reason", "r", "--channel", "comment", "--reference", "9#c1",
                       "--id", "tool-K1c", "--confidential", "--draft", "private/repos/tool/disclosures/k.md"])
            e = next((x for x in _common.load_register() if x["id"] == "tool-K1c"), {})
            check("new --id --confidential: own id, confidential part of the record",
                  rc == 0 and e.get("confidential") is True and e.get("record") == "tool" and not is_public(e)
                  and "tool-K1c" in [x["id"] for x in _common.load_json(root / "private/repos/tool/disclosures/register.json", [])])
            check("new with an existing id refused", main(["new", "--repo", "acme/tool", "--short", "tool",
                  "--finding", "f", "--severity-class", "non-critical", "--reason", "r", "--channel", "issue",
                  "--reference", "1", "--id", "tool-01"]) == 2)
            # record_or_abort: a foreign repository without a record never goes out
            stray = root / "drafts" / "s.md"
            pol = {"blob_sha": None, "checked_at": "2026-10-12", "versions": "v", "channel": "c", "scope": "s",
                   "deadlines": "d", "required_content": {}, "response_days": None, "result": "report"}
            dmeta = {"id": "stray-01", "channel": "issue", "repo": "other/repo", "title": "t", "finding": "f",
                     "severity_class": "non-critical", "severity_reason": "r", "upstream_ref": "main@x", "policy": pol}

            def write_draft(path, m, body="**Summary** text."):
                write_text(path, "# internal\n\n```json disclosure\n" + json.dumps(m, indent=2)
                           + "\n```\n\n<!-- TEXT -->\n" + body + "\n")
                return path
            write_draft(stray, dmeta)
            check("foreign repository without a record refused before anything goes out",
                  _raises(lambda: _submit.prepare(stray, ("issue",))))
            write_draft(stray, {**dmeta, "repo": "me/own", "id": "own-02"})
            check("own repository may stay in the root", _submit.prepare(stray, ("issue",))[0]["id"] == "own-02")
            # posted: comment on an advisory, posted by hand
            pd = write_draft(root / "private/repos/tool/disclosures/K2c.md",
                             {**dmeta, "id": "tool-K2c", "channel": "comment", "repo": "acme/tool",
                              "advisory": "GHSA-aaaa-bbbb-cccc"})
            url = "https://github.com/acme/tool/security/advisories/GHSA-aaaa-bbbb-cccc#advisory-comment-77"
            check("posted without approval refused", posted(pd, url) == 1)
            check("approval granted", approval_mod.main(["grant", str(pd), "--action", "comment", "--note", "t"]) == 0
                  and (root / "private/repos/tool/disclosures/approvals/tool-K2c.approval").exists())
            check("posted with a link outside the repository refused",
                  _raises(lambda: posted(pd, "https://github.com/other/x/issues/1")))
            check("posted with http refused", _raises(lambda: posted(pd, url.replace("https", "http"))))
            check("posted registers the entry", posted(pd, url, account="me") == 0)
            e = next((x for x in _common.load_register() if x["id"] == "tool-K2c"), {})
            check("posted: confidential, record, reference from the advisory and fragment",
                  e.get("confidential") is True and e.get("record") == "tool"
                  and e.get("reference") == "GHSA-aaaa-bbbb-cccc#advisory-comment-77" and e.get("url") == url
                  and not (root / "private/repos/tool/disclosures/approvals/tool-K2c.approval").exists())
            check("posted twice refused", posted(pd, url) == 1)
            # watch: reply drafts and reports per record
            check("reply draft in the record's confidential folder",
                  dw.reply_path({"id": "tool-01", "record": "tool"}, 5)
                  == "private/repos/tool/disclosures/reply-drafts/tool-01-5.md")
            res = {"time": "2026-10-12T10:00:00Z", "entries": [{"id": "tool-01"}, {"id": "own-01"}],
                   "repos": [{"repo": "acme/tool"}], "own_repos": [{"repo": "me/own"}],
                   "errors": ["tool-01: x", "acme/tool: y", "mailbox: z"], "status_changes": [("tool-01", "a", "b")],
                   "deadlines": [], "mailbox": [{"uid": 1}]}
            parts = dw.split_by_record(res, _common.load_register(), {"acme/tool": {"record": "repos/tool"}})
            check("watch: record part has its entry, section and errors",
                  [r["id"] for r in parts["tool"]["entries"]] == ["tool-01"] and parts["tool"]["repos"]
                  and parts["tool"]["errors"] == ["tool-01: x", "acme/tool: y"] and parts["tool"]["mailbox"] is None)
            check("watch: own part keeps own repos, mailbox, other errors",
                  [r["id"] for r in parts[""]["entries"]] == ["own-01"] and parts[""]["own_repos"]
                  and parts[""]["mailbox"] and parts[""]["errors"] == ["mailbox: z"])
        finally:
            for n, v in saved.items():
                setattr(_common, n, v)
            globals()["ROOT"], _submit.ROOT, _submit.FETCH_BLOB = saved_mod
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    after = real_readme.read_bytes() if real_readme.exists() else None
    check("B1: the real root overview was not touched", after == real_before)
    return ok, total


def _raises(fn) -> bool:
    try:
        fn()
    except DisclosureError:
        return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Register of upstream disclosures")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check")
    sub.add_parser("readme")
    n = sub.add_parser("new")
    for k in ("repo", "short", "finding", "severity-class", "reason", "channel", "reference"):
        n.add_argument(f"--{k}", required=True)
    for k in ("url", "created", "account", "upstream-ref", "draft", "notes"):
        n.add_argument(f"--{k}", default="")
    n.add_argument("--response-days", type=int, default=None)
    n.add_argument("--response-workdays", type=int, default=None)
    n.add_argument("--policy-blob", default=None)
    n.add_argument("--id", default=None, help="the draft's ID instead of the next free <short>-NN")
    n.add_argument("--confidential", action="store_true", help="keep the entry in the confidential part")
    n.add_argument("--record", default=None, help="folder below repos/ (default: from --draft or 'Upstream')")
    u = sub.add_parser("publish", help="after disclosure: lift the embargo")
    u.add_argument("id")
    u.add_argument("--reason", default="")
    st = sub.add_parser("set", help="set status and the optional dashboard fields of one entry")
    st.add_argument("id")
    st.add_argument("--status", choices=STATUS_VALUES)
    st.add_argument("--on", default=None, help="date of the status change (default today)")
    for k in SET_FIELDS:
        st.add_argument(f"--{k.replace('_', '-')}", dest=k, default=None)
    m = sub.add_parser("migrate", help="move a reviewed repository's entries out of the root registers")
    m.add_argument("--record", required=True)
    m.add_argument("--dry-run", action="store_true")
    ps = sub.add_parser("posted", help="register a disclosure that had to be posted by hand")
    ps.add_argument("draft")
    ps.add_argument("--url", required=True)
    for k in ("reference", "created", "account"):
        ps.add_argument(f"--{k}", default="")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.cmd:
        ap.error("give a command or --self-test")
    try:
        if a.cmd == "posted":
            return posted(Path(a.draft), a.url, a.reference, a.created, a.account)
        entries = load_register()
        if a.cmd == "migrate":
            return migrate(entries, a.record, a.dry_run)
        if a.cmd == "set":
            e = set_fields(entries, a.id, {k: getattr(a, k) for k in SET_FIELDS}, a.status, a.on)
            save_register(entries)
            write_readme(entries)
            out(f"OK: {e['id']} updated (status {e.get('status')})")
            return 0
        if a.cmd == "publish":
            e = publish(entries, a.id, a.reason)
            save_register(entries)
            write_readme(entries)
            out(f"OK: {e['id']} marked published (state only), draft stays at {e.get('draft') or '-'}")
            return 0
        if a.cmd == "check":
            errors = check(entries)
            for f in errors:
                out(f"ERROR: {f}")
            out(f"register: {len(entries)} entries, {len(errors)} errors")
            return 1 if errors else 0
        if a.cmd == "readme":
            write_readme(entries)
            out(f"OK: overviews generated from {len(entries)} entries")
            return 0
        entry = {
            "id": a.id or next_id(entries, a.short), "repo": check_repo(a.repo),
            "finding": a.finding, "severity_class": a.severity_class,
            "severity_reason": a.reason, "channel": a.channel,
            "reference": a.reference, "url": a.url, "created": a.created or now_iso(),
            "account": a.account, "upstream_ref": a.upstream_ref, "draft": a.draft,
            "status": "open", "last_checked": None, "notes": a.notes,
            "links": [], "comments_seen": 0,
            "response_days": a.response_days, "response_workdays": a.response_workdays,
            "policy_blob": a.policy_blob,
        }
        if a.confidential:
            entry["confidential"] = True
        record = check_record(a.record) if a.record else record_of(entry, a.draft)
        if record:
            entry["record"] = record
        for k in ("response_days", "response_workdays"):
            if entry[k] is not None and entry[k] <= 0:
                raise DisclosureError(f"--{k.replace('_', '-')} must be positive")
        if (a.channel in ("advisory", "email") or a.confidential) and a.draft \
                and not is_under_private(ROOT / a.draft):
            raise DisclosureError("confidential disclosure: the draft must be under private/ (embargo)")
        if any(x.get("id") == entry["id"] for x in entries):
            raise DisclosureError(f"{entry['id']} is already in the register")
        errors = check(entries + [entry])
        if errors:
            for f in errors:
                out(f"ERROR: {f}")
            return 1
        entries.append(entry)
        save_register(entries)
        write_readme(entries)
        out(f"OK: {entry['id']} registered")
        return 0
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
