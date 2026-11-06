#!/usr/bin/env python3
"""Submit a confidential disclosure via GitHub private vulnerability reporting.

    POST repos/<owner>/<repo>/security-advisories/reports

Schema checked against the GitHub REST OpenAPI description
(github/rest-api-description, api.github.com.json, info.version 1.1.4, read
2026-10-10): required summary (<=1024) and description (<=65535); severity
(critical|high|medium|low) OR cvss_vector_string, not both; cwe_ids
(list of strings); vulnerabilities[] with package.ecosystem (required, enum) and
package.name, vulnerable_version_range, patched_versions, vulnerable_functions -
no further fields; start_private_fork (bool). Response 201 = repository advisory
(ghsa_id, html_url, created_at, state).

The default is the dry run: show the payload, check the schema, leak scan,
policy check (field "policy", current SECURITY.md per GET - see _submit.py; blocks
with exit 1), read the PVR status. Submission only with --submit AND a valid
hash-bound approval (private/disclosures/approvals/<id>.approval, action=advisory).
The approval is consumed right before the post (a crash afterwards cannot leave a
reusable approval); afterwards GHSA ID and URL go into the register.
The leak scan covers EVERYTHING that is sent: summary, description, and every other
field of the payload (vulnerabilities, cvss, cwe_ids ...) serialised as JSON.
A draft whose ID is already in the register is never submitted again: the dry run
reports "ALREADY SUBMITTED" (exit 0), --submit refuses (exit 1).

Draft (Markdown):

    ```json disclosure
    {
      "id": "graphify-01", "channel": "advisory", "repo": "owner/name",
      "summary": "English one-line summary",
      "severity": "high",
      "cwe_ids": ["CWE-78"],
      "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "pkg"},
                           "vulnerable_version_range": "<= 1.2.3"}],
      "finding": "short title", "severity_class": "critical",
      "severity_reason": "...", "upstream_ref": "main@<sha>, v1.2.3"
    }
    ```
    <!-- TEXT -->
    English description (Markdown) - goes out as "description".

    python tools/disclosures/advisory_submit.py <draft.md>             # dry run
    python tools/disclosures/advisory_submit.py <draft.md> --submit    # with approval
    python tools/disclosures/advisory_submit.py --self-test

Exit 0 ok, 1 schema/leak error, no approval or already submitted (--submit), 2 operator error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from forge import forge_of  # noqa: E402
from _submit import (already_submitted_exit, approval_or_abort, leak_check,  # noqa: E402
                     policy_or_abort, prepare, register_entry, sending, show)
from leak_scan import scan  # noqa: E402
from _common import (AlreadySubmitted, DisclosureError, GhNotFound, PolicyError, err,  # noqa: E402
                     out)

ECOSYSTEMS = ("rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust",
              "erlang", "actions", "pub", "other", "swift")
SEVERITIES = ("critical", "high", "medium", "low")
VULN_FIELDS = {"package", "vulnerable_version_range", "patched_versions", "vulnerable_functions"}
CWE_RE = re.compile(r"^CWE-\d+$")


def build_payload(meta, description):
    n = {"summary": meta.get("summary", ""), "description": description}
    for k in ("severity", "cvss_vector_string", "cwe_ids", "vulnerabilities", "start_private_fork"):
        if meta.get(k) not in (None, "", []):
            n[k] = meta[k]
    return n


def outgoing_texts(payload):
    """Every value of the payload as text for the leak scan (strings as they are, the rest
    serialised as JSON) - nothing that is sent may bypass the scan."""
    return [v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
            for v in payload.values()]


def check_schema(n):
    f = []
    for k in ("summary", "description"):
        if k in n and not isinstance(n[k], str):
            f.append(f"{k} must be a string, not {type(n[k]).__name__}")
    if not n.get("summary"):
        f.append("summary missing")
    elif isinstance(n["summary"], str) and len(n["summary"]) > 1024:
        f.append("summary > 1024 characters")
    if not n.get("description"):
        f.append("description missing")
    elif isinstance(n["description"], str) and len(n["description"]) > 65535:
        f.append("description > 65535 characters")
    has_sev, has_cvss = bool(n.get("severity")), bool(n.get("cvss_vector_string"))
    if has_sev == has_cvss:
        f.append("set exactly one of severity / cvss_vector_string")
    if has_sev and n["severity"] not in SEVERITIES:
        f.append(f"severity {n['severity']!r} not in {SEVERITIES}")
    if has_cvss and not str(n["cvss_vector_string"]).startswith("CVSS:"):
        f.append("cvss_vector_string does not start with 'CVSS:'")
    cwe = n.get("cwe_ids", [])
    if not isinstance(cwe, list) or any(not isinstance(c, str) or not CWE_RE.match(c) for c in cwe):
        f.append("cwe_ids must be a list like ['CWE-78']")
    vul = n.get("vulnerabilities", [])
    if not isinstance(vul, list):
        f.append("vulnerabilities must be a list")
        vul = []
    for i, v in enumerate(vul):
        if not isinstance(v, dict):
            f.append(f"vulnerabilities[{i}] is not an object")
            continue
        extra = set(v) - VULN_FIELDS
        if extra:
            f.append(f"vulnerabilities[{i}]: unknown fields {sorted(extra)}")
        pkg = v.get("package")
        if not isinstance(pkg, dict) or pkg.get("ecosystem") not in ECOSYSTEMS:
            f.append(f"vulnerabilities[{i}].package.ecosystem missing/invalid ({ECOSYSTEMS})")
        if "vulnerable_functions" in v and not isinstance(v["vulnerable_functions"], list):
            f.append(f"vulnerabilities[{i}].vulnerable_functions must be a list")
    if "start_private_fork" in n and not isinstance(n["start_private_fork"], bool):
        f.append("start_private_fork must be bool")
    allowed = {"summary", "description", "severity", "cvss_vector_string", "cwe_ids",
               "vulnerabilities", "start_private_fork"}
    if set(n) - allowed:
        f.append(f"unknown fields {sorted(set(n) - allowed)}")
    return f


def self_test() -> int:
    good = {"summary": "s", "description": "d", "severity": "high", "cwe_ids": ["CWE-78"],
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "x"},
                                 "vulnerable_version_range": "<= 1"}]}
    cases = [
        (good, 0),
        ({**good, "cvss_vector_string": "CVSS:3.1/AV:N"}, 1),            # both
        ({k: v for k, v in good.items() if k != "severity"}, 1),          # neither
        ({**good, "severity": "urgent"}, 1),
        ({**good, "cwe_ids": ["78"]}, 1),
        ({**good, "vulnerabilities": [{"package": {"ecosystem": "pypi"}}]}, 1),
        ({**good, "vulnerabilities": [{"package": {"ecosystem": "npm"}, "x": 1}]}, 1),
        ({**good, "summary": "x" * 1025}, 1),
        ({**good, "credits": []}, 1),
        ({**good, "summary": ["not", "a", "string"]}, 1),                 # no traceback
        ({**good, "summary": 12345}, 1),
        ({**good, "description": {"a": 1}}, 1),
        ({**good, "description": 7}, 1),
    ]
    bad = 0
    for n, expected in cases:
        actual = 1 if check_schema(n) else 0
        if actual != expected:
            bad += 1
            out(f"ERROR: self-test {json.dumps(n)[:80]}: expected {expected}, got {actual}")
    total = len(cases)
    # the leak scan sees every field that is sent, not only summary and description
    texts = " ".join(outgoing_texts({**good, "vulnerabilities": [
        {"package": {"ecosystem": "pip", "name": "x"}, "vulnerable_functions": ["/home/user/secret"]}]}))
    for ok, label in ((any(f[0] == "ERROR" for f in scan(texts, names=[])), "leak scan covers vulnerabilities"),
                      (not any(f[0] == "ERROR" for f in scan(" ".join(outgoing_texts(good)), names=[])),
                       "clean payload passes")):
        total += 1
        if not ok:
            bad += 1
            out(f"ERROR: self-test {label}")
    out(f"advisory_submit self-test: {total - bad}/{total} OK")
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PVR disclosure from a draft (default: dry run)")
    ap.add_argument("draft", nargs="?")
    ap.add_argument("--submit", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="default; only for clarity")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.draft:
        ap.error("give a draft")
    if a.submit and a.dry_run:
        ap.error("--submit and --dry-run are mutually exclusive")
    draft = Path(a.draft)
    try:
        meta, text, raw = prepare(draft, ("advisory",), ("repo", "summary"))
        f = forge_of(meta)
        if "advisory" not in f.features:
            raise DisclosureError(f"forge {f.alias} ({f.kind}) has no private vulnerability reporting - "
                                  "GitLab: issue_submit.py with \"confidential\": true; otherwise mail_report.py")
        payload = build_payload(meta, text)
        errors = check_schema(payload)
        head = {"Channel": "advisory (private vulnerability reporting)", "Repo": meta["repo"],
                "summary": payload["summary"],
                "severity/cvss": payload.get("severity") or payload.get("cvss_vector_string"),
                "cwe_ids": payload.get("cwe_ids", []),
                "vulnerabilities": json.dumps(payload.get("vulnerabilities", []))}
        show(head, text, raw)
        for problem in errors:
            out(f"  SCHEMA ERROR: {problem}")
        clean = leak_check(meta, *outgoing_texts(payload))
        try:
            pvr = bool((f.get(f"repos/{meta['repo']}/private-vulnerability-reporting") or {}).get("enabled"))
        except GhNotFound:
            pvr = None
        out(f"PVR at {meta['repo']}: {pvr}")
        if errors or not clean:
            out("ERROR: schema or leak scan - do not submit")
            return 1
        policy_or_abort(meta, text)
        if pvr is not True:
            out("ERROR: PVR is not enabled - choose another channel (channel.py)")
            return 1
        if not a.submit:
            out("DRY RUN: nothing submitted. Submit only with approval + --submit.")
            return 0
        approval_or_abort(meta, raw, "advisory")
        account = f.whoami()
        with sending(meta["id"]):       # approval consumed before the post
            answer = f.post(f"repos/{meta['repo']}/security-advisories/reports", payload)
        ghsa = answer.get("ghsa_id")
        if not ghsa:
            raise DisclosureError(f"answer without ghsa_id: {str(answer)[:200]}")
        entry = register_entry(meta, draft, "advisory", ghsa, answer.get("html_url"),
                               answer.get("created_at"), account,
                               f"state={answer.get('state')}")
        out(f"OK: advisory {ghsa} submitted: {answer.get('html_url')} - register {entry['id']}")
        return 0
    except AlreadySubmitted as exc:
        return already_submitted_exit(exc, a.submit)
    except PolicyError as exc:
        err(f"ERROR: {exc}")
        return 1
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
