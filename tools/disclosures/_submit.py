"""Shared flow of the submit tools (issue, comment, advisory, mail).

Every disclosure that leaves the machine passes the same stages:

1. read the draft (format see _common.read_draft)
2. check required fields; the disclosure ID must not be in the register yet
   (otherwise AlreadySubmitted: the dry run reports it, --submit refuses - never twice)
3. leak scan over the text that goes out - an error finding aborts
4. check against the upstream security policy (field "policy"): field present, every
   required content true, result "report", and the upstream SECURITY.md is still the
   same per GET (blob SHA) - otherwise abort (PolicyError)
5. dry run (default): show exactly what would be sent, plus SHA-256
6. only with --submit or --send: if switched on in .env (disclosure_codex_check=on), the
   Codex cross-check for exactly this draft hash must say CHECK: CONFIRMED (codex_check.py);
   then check the hash-bound one-time approval, consume (reserve) the approval, send,
   write the register entry, regenerate the overview. The approval is consumed BEFORE the
   external call (see sending()): a crash after posting cannot leave a reusable approval;
   the Codex check record under private/disclosures/checks/ stays as evidence

Field "policy" in the draft's JSON block (result of step 3 in the skill
finding-disclosure, skeleton from 'channel.py --policy <o/r>'):

    "policy": {
      "blob_sha": "<blob SHA of the SECURITY.md read>" | null (upstream has none),
      "path": "SECURITY.md",              # as read; for an organisation default
      "repo": "<owner>/.github",          # only then (same owner) - otherwise omit; any other
                                          # repository than the disclosure's is refused
      "checked_at": "2026-10-10",
      "versions": "...", "channel": "...", "scope": "...", "deadlines": "...",
      "required_content": {"Steps to reproduce": true, ...},
      "response_days": null | <int>, "response_workdays": null | <int>,
      "result": "report" | "reclassify" | "do-not-report"
    }

An empty "required_content" is only allowed if the upstream has no policy
(blob_sha null) or if it is not a security report (channel issue/comment,
severity_class non-critical) - the required content of a SECURITY.md applies to
security reports.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from contextlib import contextmanager
from urllib.parse import quote

from _common import (POLICY_RESULTS, ROOT, SECURITY_PATHS, SEVERITY_CLASSES, AlreadySubmitted,
                     DisclosureError, GhNotFound, PolicyError, check_approval, check_claudex, check_repo,
                     consume_approval, err, gh_get, is_under_private, load_register,
                     load_watch_config, out, read_draft, record_of, records_enabled, register_lock,
                     save_register, sha256_bytes)
from forge import forge_of, get_forge, target_of
from leak_scan import scan

# Channels for which the policy check is mandatory (reactions in the own repository
# do not go through prepare() and need none).
CHANNELS_WITH_POLICY = ("issue", "comment", "advisory", "email")
POLICY_TEXT_FIELDS = ("checked_at", "versions", "channel", "scope", "deadlines")
_ANGLE_PLACEHOLDER = re.compile(r"^\s*<[^<>]*>\s*$")

# Replaceable for self-tests: (repo, path) -> blob SHA at the default branch or None.
FETCH_BLOB = None


def find_registered(disclosure_id):
    """Register entry with this ID, or None."""
    return next((e for e in load_register() if e.get("id") == disclosure_id), None)


def prepare(draft: Path, expected_channels, required=()):
    meta, text, raw = read_draft(draft)
    if meta.get("channel") not in expected_channels:
        raise DisclosureError(f"draft has channel={meta.get('channel')!r}, expected {expected_channels}")
    registered = find_registered(meta.get("id"))
    if meta.get("id") and registered is not None:
        raise AlreadySubmitted(registered)
    if (meta["channel"] in ("advisory", "email") or meta.get("confidential")) and not is_under_private(draft):
        raise DisclosureError("confidential channel: the draft must be under private/ "
                              "(embargo until publication, then 'register.py publish')")
    for k in ("id", "finding", "severity_class", "severity_reason", "upstream_ref") + tuple(required):
        if not meta.get(k):
            raise DisclosureError(f"draft: field {k!r} missing or empty")
    if meta["severity_class"] not in SEVERITY_CLASSES:
        raise DisclosureError(f"severity_class {meta['severity_class']!r} - allowed {SEVERITY_CLASSES}")
    if meta.get("repo"):
        forge_of(meta).check_repo(meta["repo"])
    record_or_abort(meta, draft)
    if "exposure" in meta and meta["exposure"] not in ("network", "local"):
        raise DisclosureError(f"draft: exposure {meta['exposure']!r} - 'network' or 'local', or remove the field")
    if "confidential" in meta and not isinstance(meta["confidential"], bool):
        raise DisclosureError("draft: confidential must be true or false")
    if not text.strip():
        raise DisclosureError("text after the marker is empty")
    if "{{" in text or "{{" in json.dumps(meta):
        raise DisclosureError("draft still contains placeholders {{...}} - fill them in first")
    return meta, text, raw


def record_or_abort(meta, draft: Path) -> str:
    """Record (reviewed repository) the draft belongs to - checked BEFORE anything goes out:
    a disclosure to a foreign repository needs a record folder, the root folders take only
    the checker's own disclosures (own repositories from watch_config 'own_repos')."""
    record = record_of(meta, draft)
    if record or not records_enabled():
        return record
    if target_of(meta) in (load_watch_config().get("own_repos") or []):
        return ""
    raise DisclosureError(f"no record for {target_of(meta)}: put the draft under private/records/<name>/disclosures/ "
                          "(confidential: private/repos/<name>/disclosures/) or set the field 'record' - "
                          "the root disclosures/ folders hold only the checker's own disclosures")


def already_submitted_exit(exc: AlreadySubmitted, submitting: bool) -> int:
    """Dry run: notice, exit 0 (nothing to do). With --submit/--send: refuse, exit 1."""
    out(str(exc))
    if submitting:
        out("ERROR: refusing to submit a disclosure that is already in the register")
        return 1
    out("DRY RUN: nothing to do.")
    return 0


EXPLOIT_KIND = "exploit detail?"


def leak_check(meta, *texts, block_exploit=False) -> bool:
    """Leak scan over everything that goes out. block_exploit=True turns the warnings of
    kind 'exploit detail?' into errors (critical finding on a public channel)."""
    findings = scan("\n".join(texts), meta.get("leak_allow", []))
    if block_exploit:
        findings = [("ERROR", k, nr, m) if k == EXPLOIT_KIND else (lv, k, nr, m)
                    for lv, k, nr, m in findings]
    for level, kind, nr, match in findings:
        shown = "<redacted>" if kind == "credentials" else match
        out(f"  {level}: line {nr}: {kind}: {shown}")
    errors = [f for f in findings if f[0] == "ERROR"]
    out(f"Leak scan: {len(errors)} errors, {len(findings) - len(errors)} warnings")
    if block_exploit and any(f[1] == EXPLOIT_KIND for f in errors):
        out("  ERROR: critical finding on a public channel: exploit details (PoC, payload, "
            "reverse shell, exploit) must not appear in the text - remove them or use the "
            "confidential channel (advisory / mail)")
    return not errors


# --------------------------------------------------------------------------- #
# Check against the upstream security policy
# --------------------------------------------------------------------------- #

def current_blob(repo: str, path: str, forge: str = None):
    """Blob SHA of a file at the default branch (GET only) or None if it does not exist.
    forge = alias from the draft (field 'forge'); absent = github.com."""
    try:
        if forge in (None, "", "github"):
            d = gh_get(f"repos/{check_repo(repo)}/contents/{quote(path)}")
        else:
            f = get_forge(forge)
            d = f.get(f"repos/{f.check_repo(repo)}/contents/{quote(path)}")
    except GhNotFound:
        return None
    if not isinstance(d, dict) or d.get("type") != "file":
        return None
    return d.get("sha")


def _is_empty(value) -> bool:
    return not isinstance(value, str) or not value.strip() or bool(_ANGLE_PLACEHOLDER.match(value))


def check_policy(meta, fetch=None):
    """List of reasons that block approval and submission (empty = fine).
    Reads the current blob SHA per GET - the check must match today's text."""
    fetch = fetch or FETCH_BLOB or (lambda r, p: current_blob(r, p, meta.get("forge")))
    if meta.get("channel") not in CHANNELS_WITH_POLICY:
        return []
    pol = meta.get("policy")
    if not isinstance(pol, dict):
        return ["field 'policy' missing: run 'channel.py --policy <o/r>' first and enter the "
                "check (skill finding-disclosure, step 3) in the draft"]
    f = []
    if "blob_sha" not in pol:
        f.append("policy.blob_sha missing (null only if the upstream has no SECURITY.md)")
    blob = pol.get("blob_sha")
    if blob is not None and (not isinstance(blob, str) or not re.fullmatch(r"[0-9a-f]{40}", blob)):
        f.append(f"policy.blob_sha {blob!r} is not a blob SHA (40 hex characters)")
        blob = None
    if blob is not None and _is_empty(pol.get("path")):
        f.append("policy.path missing")
    for k in POLICY_TEXT_FIELDS:
        if _is_empty(pol.get(k)):
            f.append(f"policy.{k} missing or placeholder - enter the assessment")
    for k in ("response_days", "response_workdays"):
        v = pol.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v <= 0):
            f.append(f"policy.{k} must be null or a positive integer")
    rc = pol.get("required_content")
    if not isinstance(rc, dict):
        f.append("policy.required_content missing (object {required content: true/false})")
    else:
        unmet = [k for k, v in rc.items() if v is not True]
        if unmet:
            f.append("required content of the policy not met: " + ", ".join(unmet))
        not_a_security_report = (meta.get("channel") in ("issue", "comment")
                                 and meta.get("severity_class") == "non-critical")
        if not rc and "blob_sha" in pol and pol.get("blob_sha") is not None and not not_a_security_report:
            f.append("policy.required_content is empty although a policy was read - "
                     "enter and assess the required content items one by one")
    res = pol.get("result")
    if res not in POLICY_RESULTS:
        f.append(f"policy.result {res!r} - allowed {POLICY_RESULTS}")
    elif res != "report":
        f.append(f"policy.result is {res!r}: per the policy, do not report in this form "
                 "(reclassify or do not report, reason in the internal part)")
    # State of the policy: is it still the same today?
    # Always the disclosure's own repository: a draft must not choose another repository's
    # policy. Only the organisation default <owner>/.github (same owner) may be named in
    # policy.repo, for a SECURITY.md that is inherited from it.
    repo = meta.get("repo")
    if not isinstance(repo, str) or not repo:
        f.append("no repository for the policy check (field repo of the disclosure)")
        return f
    pol_repo = pol.get("repo")
    source = repo
    if pol_repo not in (None, "", repo):
        if pol_repo == f"{repo.split('/', 1)[0]}/.github":
            source = pol_repo
        else:
            f.append(f"policy.repo {pol_repo!r} differs from the disclosure's repo {repo!r} "
                     "(only the organisation default <owner>/.github is allowed) - "
                     "the policy of another repository does not apply")
            return f
    if "blob_sha" in pol and pol.get("blob_sha") is None:
        owner = repo.split("/", 1)[0]
        for r in (repo, f"{owner}/.github"):
            for p in SECURITY_PATHS:
                actual = fetch(r, p)
                if actual:
                    f.append(f"policy changed, check again: {r}:{p} exists now "
                             f"(blob {actual[:12]}), the check was 'no SECURITY.md'")
                    return f
    elif blob and pol.get("path"):
        actual = fetch(source, pol["path"])
        if actual is None:
            f.append(f"policy changed, check again: {source}:{pol['path']} no longer exists")
        elif actual != blob:
            f.append(f"policy changed, check again: {source}:{pol['path']} checked blob "
                     f"{blob[:12]}, current {actual[:12]}")
    return f


def required_content_hints(meta, text: str):
    """Soft cross-check (WARNING, does not block): does a keyword of every required
    content item marked as met occur in the text?"""
    pol = meta.get("policy") if isinstance(meta.get("policy"), dict) else {}
    rc = pol.get("required_content") if isinstance(pol.get("required_content"), dict) else {}
    t = text.lower()
    hints = []
    for k, v in rc.items():
        words = [w for w in re.findall(r"[a-z]{4,}", str(k).lower())
                 if w not in ("description", "potential", "vulnerability", "issue", "with", "your", "possible")]
        if v is True and words and not any(w in t for w in words):
            hints.append(f"required content {k!r} marked as met, keyword not found in the text")
    return hints


def policy_or_abort(meta, text: str = "", fetch=None) -> None:
    """Prints the result of the check; PolicyError if it blocks."""
    if meta.get("channel") not in CHANNELS_WITH_POLICY:
        return
    pol = meta.get("policy") if isinstance(meta.get("policy"), dict) else {}
    reasons = check_policy(meta, fetch)
    for h in required_content_hints(meta, text):
        out(f"  WARNING: policy: {h}")
    if reasons:
        for r in reasons:
            out(f"  ERROR: policy: {r}")
        raise PolicyError("policy check blocks (" + str(len(reasons))
                          + " reason(s), see above) - no approval, no submission")
    out(f"Policy: ok ({pol.get('path') or 'no SECURITY.md'} blob "
        f"{(pol.get('blob_sha') or '-')[:12]}, checked {pol.get('checked_at')}, result report, "
        + (f"{len(pol['required_content'])} required content item(s) met)" if pol.get("required_content")
           else "required content not applicable)"))


def show(head: dict, text: str, raw: bytes) -> None:
    out("=" * 72)
    for k, v in head.items():
        out(f"{k}: {v}")
    out("-" * 72)
    out(text)
    out("=" * 72)
    out(f"SHA-256 of the draft: {sha256_bytes(raw)}")


CLAUDEX_COMMANDS = {"text check": ("run", "disclosure_codex_check"),
                    "finding validation": ("finding", "claudex_finding_check"),
                    "exposure pass": ("exposure", "claudex_exposure_check")}


def codex_check_or_abort(meta, raw) -> None:
    """Codex gates (each only if switched on in .env): text check (_common.check_codex), finding
    validation and exposure pass (_common.check_form). The first that blocks raises PolicyError."""
    for ok, label, reason in check_claudex(meta, raw):
        cmd, switch = CLAUDEX_COMMANDS[label]
        if not ok:
            raise PolicyError(f"{reason}. Run 'python tools/disclosures/codex_check.py {cmd} <draft> "
                              f"--source quarantine/<name>' first (switch {switch} in .env).")
        if reason == "ok":
            out(f"Codex {label}: ok")


def approval_or_abort(meta, raw, action):
    codex_check_or_abort(meta, raw)
    ok, reason = check_approval(meta["id"], raw, action)
    if not ok:
        raise DisclosureError(f"no valid approval: {reason}. Present the text first, then "
                              f"'python tools/disclosures/approval.py grant <draft> --action {action}' "
                              "- only on the client's instruction.")


@contextmanager
def sending(disclosure_id):
    """Around the external call of a submit tool: consumes (reserves) the one-time approval
    BEFORE the call, so that a crash after the post cannot leave a reusable approval.
    Only the approval file is deleted - the Codex check record stays as evidence.
    If the block fails, say so clearly: the approval is gone and a new grant is needed
    (and the target should be checked first - the post may have gone through)."""
    consume_approval(disclosure_id)
    try:
        yield
    except BaseException:
        err(f"NOTE: the approval for {disclosure_id} is CONSUMED. Check whether the "
            "disclosure was posted before you grant a new approval "
            "('approval.py grant ...', only on the client's instruction).")
        raise


def register_entry(meta, draft: Path, channel, reference, url, created, account, note=""):
    with register_lock():
        return _register_entry(meta, draft, channel, reference, url, created, account, note)


def _register_entry(meta, draft: Path, channel, reference, url, created, account, note=""):
    entries = load_register()
    try:
        draft_rel = draft.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        draft_rel = str(draft)
    pol = meta.get("policy") if isinstance(meta.get("policy"), dict) else {}
    entry = {
        "id": meta["id"], "repo": meta.get("repo", ""), "finding": meta["finding"],
        # code host (absent = github.com) and GitLab's confidential issue - both decide
        # where the watch reads and whether the entry stays in the confidential register
        **({"forge": meta["forge"]} if meta.get("forge") not in (None, "", "github") else {}),
        **({"confidential": True} if meta.get("confidential") else {}),
        # reviewed repository the entry is stored with ('' = the checker itself, root folders)
        **({"record": record_of(meta, draft)} if record_of(meta, draft) else {}),
        "severity_class": meta["severity_class"], "severity_reason": meta["severity_reason"],
        "channel": channel, "reference": str(reference), "url": url or "", "created": created,
        "account": account, "upstream_ref": meta["upstream_ref"], "draft": draft_rel,
        "status": "open", "last_checked": None, "notes": note,
        "links": [], "comments_seen": 0,
        # From the policy check: promised response time (disclosure_watch.py reports
        # "deadline passed without response") and which version of the policy applied.
        "response_days": pol.get("response_days"),
        "response_workdays": pol.get("response_workdays"),
        "policy_blob": pol.get("blob_sha"),
    }
    entries.append(entry)
    save_register(entries)
    from register import write_readme
    write_readme(entries)
    consume_approval(meta["id"])
    return entry
