#!/usr/bin/env python3
"""Grant or show a hash-bound one-time approval for a disclosure.

An approval is the file private/disclosures/approvals/<id>.approval with
  action=<issue|comment|advisory|email|reaction>
  sha256=<SHA-256 of the draft file>
The submit tool only submits if the hash matches the draft, and deletes the file
afterwards. Every change to the draft after the approval invalidates it.

Before every approval (issue, comment, advisory, email) the check against the
upstream security policy is verified (field "policy", see _submit.py): if it is
missing, a required content item is false, the result is not "report", or the current
SECURITY.md (blob SHA per GET) differs from the checked state, there is no approval.
A draft whose ID is already in the register gets no approval either (it was submitted).
If the Codex cross-check is switched on in .env (disclosure_codex_check=on), "grant" also
requires a CHECK: CONFIRMED record for exactly this draft hash (codex_check.py).

  python tools/disclosures/approval.py show   <draft.md>
  python tools/disclosures/approval.py grant  <draft.md> --action issue --note "client instruction 2026-10-10"
  python tools/disclosures/approval.py status <id>
  python tools/disclosures/approval.py revoke <id>
  python tools/disclosures/approval.py --self-test

WARNING: "grant" ONLY after the client has seen and approved exactly this text.
This is a brake with a paper trail, not a vault: whoever can write the file can
approve themselves. An agent that grants without instruction breaks the rule, not
the mechanism.

Exit 0 ok, 1 leak finding, policy check blocks or already submitted (grant refused),
2 operator error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _submit  # noqa: E402
import _common  # noqa: E402
from _submit import codex_check_or_abort, find_registered, policy_or_abort  # noqa: E402
from _common import (ROOT, AlreadySubmitted, DisclosureError, PolicyError, approval_path,  # noqa: E402
                     consume_approval, err, out, read_draft, sha256_bytes, write_approval)
from leak_scan import scan  # noqa: E402

ACTIONS = ("issue", "comment", "advisory", "email", "reaction")


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(p)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Approval of a disclosure")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    z = sub.add_parser("show")
    z.add_argument("draft")
    g = sub.add_parser("grant")
    g.add_argument("draft")
    g.add_argument("--action", required=True, choices=ACTIONS)
    g.add_argument("--note", required=True, help="who approved when")
    s = sub.add_parser("status")
    s.add_argument("id")
    r = sub.add_parser("revoke")
    r.add_argument("id")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.cmd:
        ap.print_help()
        return 2
    try:
        if a.cmd in ("status", "revoke"):
            p = approval_path(a.id)
            if a.cmd == "revoke":
                consume_approval(a.id)
                out(f"OK: {p.name} removed")
                return 0
            out(p.read_text(encoding="utf-8") if p.exists() else f"no approval for {a.id}")
            return 0
        meta, text, raw = read_draft(Path(a.draft))
        head = "\n".join(str(meta.get(k, "")) for k in ("title", "summary", "subject"))
        findings = scan(head + "\n" + text, meta.get("leak_allow", []))
        errors = [f for f in findings if f[0] == "ERROR"]
        if a.cmd == "show":
            out(f"ID: {meta.get('id')}  Channel: {meta.get('channel')}  Repo/target: "
                f"{meta.get('repo') or meta.get('to')}")
            out(f"Head: {head.strip()}")
            out("-" * 72)
            out(text)
            out("-" * 72)
            for f in findings:
                out(f"  {f[0]}: line {f[2]}: {f[1]}: "
                    f"{'<redacted>' if f[1] == 'credentials' else f[3]}")
            out(f"Leak scan: {len(errors)} errors, {len(findings) - len(errors)} warnings")
            out(f"SHA-256: {sha256_bytes(raw)}")
            registered = find_registered(meta.get("id"))
            if registered is not None:
                out(str(AlreadySubmitted(registered)))
            try:
                policy_or_abort(meta, text)
            except PolicyError as exc:
                out(f"ERROR: {exc}")
                return 1
            ok_c = True
            for ok_g, label, reason_g in _common.check_claudex(meta, raw):
                out(f"Codex {label}: {reason_g}" if ok_g else f"ERROR: Codex {label}: {reason_g}")
                ok_c = ok_c and ok_g
            return 1 if errors or not ok_c else 0
        if errors:
            out(f"ERROR: leak scan reports {len(errors)} errors - no approval")
            return 1
        if meta.get("channel") != a.action:
            raise DisclosureError(f"draft has channel={meta.get('channel')}, approval for {a.action}")
        registered = find_registered(meta.get("id"))
        if registered is not None:
            out(f"ERROR: {AlreadySubmitted(registered)} - no approval")
            return 1
        policy_or_abort(meta, text)
        codex_check_or_abort(meta, raw)
        p = write_approval(meta["id"], raw, a.action, a.note, _common.record_of(meta, Path(a.draft)))
        out(f"OK: approval {_rel(p)} for sha256={sha256_bytes(raw)[:16]}...")
        return 0
    except PolicyError as exc:
        err(f"ERROR: {exc}")
        return 1
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 2


# --------------------------------------------------------------------------- #
# Self-test (no network): policy check, approval, dry run
# --------------------------------------------------------------------------- #

def self_test() -> int:
    import copy
    import json
    import tempfile

    import issue_submit
    from _submit import check_policy
    from _common import write_text

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    b1, b2 = "a" * 40, "b" * 40
    state = {("acme/tool", "SECURITY.md"): b1}

    def fetch(repo, path):
        return state.get((repo, path))

    pol = {"blob_sha": b1, "path": "SECURITY.md", "checked_at": "2026-10-10",
           "versions": "Latest 1.x supported; checked 1.4 - covered", "channel": "PVR, no public issue",
           "scope": "in scope", "deadlines": "acknowledge as soon as possible",
           "required_content": {"Steps to reproduce": True, "Potential impact": True},
           "response_days": None, "result": "report"}
    good = {"channel": "advisory", "repo": "acme/tool", "severity_class": "critical", "policy": pol}

    def with_(**changes):
        m = copy.deepcopy(good)
        for k, v in changes.items():
            if v is None and k in m["policy"] and k != "blob_sha":
                del m["policy"][k]
            else:
                m["policy"][k] = v
        return m

    def reasons(m, f=fetch):
        return check_policy(m, f)

    check("valid check", reasons(good) == [])
    without = {k: v for k, v in good.items() if k != "policy"}
    check("policy missing", any("missing" in r for r in reasons(without)))
    check("required content false", any("not met" in r and "Potential impact" in r
                                         for r in reasons(with_(required_content={"Steps to reproduce": True,
                                                                                  "Potential impact": False}))))
    check("required content not bool", any("not met" in r
                                           for r in reasons(with_(required_content={"Steps to reproduce": "yes"}))))
    check("result reclassify", any("'reclassify'" in r for r in reasons(with_(result="reclassify"))))
    check("result do-not-report", any("'do-not-report'" in r for r in reasons(with_(result="do-not-report"))))
    check("result invalid", any("allowed" in r for r in reasons(with_(result="maybe"))))
    check("blob SHA changed", any("policy changed" in r
                                  for r in reasons(good, lambda r, p: b2 if p == "SECURITY.md" else None)))
    check("SECURITY.md removed", any("no longer exists" in r for r in reasons(good, lambda r, p: None)))
    check("placeholder in text field", any("policy.scope" in r for r in reasons(with_(scope="<scope>"))))
    check("text field missing", any("policy.versions" in r for r in reasons(with_(versions=None))))
    check("deadline invalid", any("response_days" in r for r in reasons(with_(response_days=0))))
    check("empty required content for a security report", any("empty" in r for r in reasons(with_(required_content={}))))
    issue_n = {**copy.deepcopy(good), "channel": "issue", "severity_class": "non-critical"}
    issue_n["policy"]["required_content"] = {}
    check("empty required content allowed for a non-critical issue", reasons(issue_n) == [])
    none_ = with_(blob_sha=None, path=None, required_content={})
    check("without SECURITY.md (blob null) allowed", reasons(none_, lambda r, p: None) == [])
    check("without SECURITY.md, assessment still mandatory",
          any("policy.channel" in r for r in reasons(with_(blob_sha=None, path=None, required_content={},
                                                           channel=""), lambda r, p: None)))
    check("blob null, upstream has one now",
          any("exists now" in r for r in reasons(none_, lambda r, p: b2 if r == "acme/.github" else None)))
    check("blob_sha key missing", any("blob_sha missing" in r
                                      for r in reasons({**good, "policy": {k: v for k, v in pol.items()
                                                                           if k != "blob_sha"}})))
    check("reaction needs no check", check_policy({"channel": "reaction"}, fetch) == [])
    # the policy of another repository does not count (always the disclosure's repo)
    foreign = with_(repo="evil/tool")
    seen = []
    check("policy.repo of another repo refused",
          any("differs" in r for r in check_policy(foreign, lambda r, p: seen.append(r) or b1)))
    check("foreign policy repo is not even fetched", seen == [])
    check("policy.repo = own repo accepted", check_policy(with_(repo="acme/tool"), fetch) == [])
    org = {("acme/.github", "SECURITY.md"): b1}
    check("policy.repo = <owner>/.github accepted",
          check_policy(with_(repo="acme/.github"), lambda r, p: org.get((r, p))) == [])
    no_repo = {k: v for k, v in good.items() if k != "repo"}
    check("disclosure without repo: no fallback to policy.repo",
          any("no repository" in r for r in check_policy({**no_repo, "policy": {**pol, "repo": "acme/tool"}}, fetch)))

    # HTTP 403 is not 'not found' (S1-2): only 404 passes the 'no SECURITY.md' gate
    class _Proc:
        def __init__(self, text):
            self.returncode, self.stdout, self.stderr = 1, "", text

    def with_gh(text, fn):
        old = _common._gh
        _common._gh = lambda argv, stdin=None: _Proc(text)
        try:
            return fn()
        except BaseException as exc:                        # noqa: BLE001
            return exc
        finally:
            _common._gh = old

    r403 = with_gh("gh: Forbidden (HTTP 403)", lambda: _common.gh_get("repos/a/b/contents/SECURITY.md"))
    check("gh_get 403 -> DisclosureError, not GhNotFound",
          isinstance(r403, DisclosureError) and not isinstance(r403, _common.GhNotFound))
    check("gh_get 404 -> GhNotFound",
          isinstance(with_gh("gh: Not Found (HTTP 404)", lambda: _common.gh_get("x")), _common.GhNotFound))
    check("gh_get 403 with forbidden_ok -> GhNotFound",
          isinstance(with_gh("(HTTP 403)", lambda: _common.gh_get("x", forbidden_ok=True)), _common.GhNotFound))
    check("gh_get_list 403 -> DisclosureError",
          isinstance(with_gh("(HTTP 403)", lambda: _common.gh_get_list("x")), DisclosureError)
          and not isinstance(with_gh("(HTTP 403)", lambda: _common.gh_get_list("x")), _common.GhNotFound))
    check("current_blob: 403 does not read as 'no SECURITY.md'",
          isinstance(with_gh("(HTTP 403)", lambda: _submit.current_blob("a/b", "SECURITY.md")), DisclosureError))
    check("current_blob: 404 -> None", with_gh("(HTTP 404)", lambda: _submit.current_blob("a/b", "SECURITY.md")) is None)
    check("SECURITY_PATHS in GitHub's order",
          _common.SECURITY_PATHS == (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"))

    # exploit details block a critical finding on a public channel (S1-3)
    lax = _submit.leak_check({"leak_allow": []}, "Use this payload to get a reverse shell.")
    strict = _submit.leak_check({"leak_allow": []}, "Use this payload to get a reverse shell.",
                                block_exploit=True)
    check("exploit words: warning only for non-critical", lax is True)
    check("exploit words: error for critical public", strict is False)
    try:
        policy_or_abort(without, "", fetch)
        check("policy_or_abort blocks", False)
    except PolicyError:
        check("policy_or_abort blocks", True)

    # End to end without network: grant an approval and dry-run an issue
    # (the Codex cross-check has its own self-test in codex_check.py - switched off here)
    import os
    switches = ("disclosure_codex_check", "claudex_finding_check", "claudex_exposure_check")
    old_switches = {k: os.environ.get(k) for k in switches}
    for k in switches:
        os.environ[k] = "off"
    old_approvals, old_fetch = _common.APPROVALS, _submit.FETCH_BLOB
    old_reg = (_common.REGISTER, _common.REGISTER_PRIVATE)
    with tempfile.TemporaryDirectory() as td:
        _common.APPROVALS = Path(td) / "approvals"
        _common.REGISTER = Path(td) / "register.json"
        _common.REGISTER_PRIVATE = Path(td) / "register.private.json"
        _submit.FETCH_BLOB = fetch
        try:
            def draft(name, policy):
                meta = {"id": f"selftest-{name}", "channel": "issue", "repo": "acme/tool",
                        "title": "Parser drops trailing newline", "finding": "f",
                        "severity_class": "non-critical", "severity_reason": "bug without attacker",
                        "upstream_ref": "main@" + "c" * 40}
                if policy is not None:
                    meta["policy"] = policy
                p = Path(td) / f"{name}.md"
                write_text(p, "# internal\n\n```json disclosure\n" + json.dumps(meta, indent=2)
                           + "\n```\n\n<!-- TEXT -->\n**Summary**\n\nThe parser drops a newline.\n\n"
                           "**Steps to reproduce**\n\n1. Parse a file.\n\n**Potential impact**\n\nWrong output.\n")
                return p, meta["id"]

            def grant(p):
                return main(["grant", str(p), "--action", "issue", "--note", "self-test"])

            for name, pol_x in (("missing", None),
                                ("false", {**pol, "required_content": {"Steps to reproduce": False}}),
                                ("reclassify", {**pol, "result": "reclassify"})):
                p, mid = draft(name, pol_x)
                check(f"grant refused ({name})", grant(p) == 1 and not approval_path(mid).exists())
            p, mid = draft("blob", pol)
            state[("acme/tool", "SECURITY.md")] = b2
            check("grant refused (blob SHA changed)", grant(p) == 1 and not approval_path(mid).exists())
            check("dry run issue blocked (blob SHA changed)", issue_submit.main([str(p)]) == 1)
            state[("acme/tool", "SECURITY.md")] = b1
            check("dry run issue green", issue_submit.main([str(p)]) == 0)
            check("grant with valid check", grant(p) == 0 and approval_path(mid).exists())
            check("show reports the block", main(["show", str(draft("z", None)[0])]) == 1)
            # Already submitted: register entry with the same ID
            p2, mid2 = draft("done", pol)
            write_text(_common.REGISTER, json.dumps([{"id": mid2, "channel": "issue", "reference": "7",
                                                      "created": "2026-10-10T00:00:00Z"}]))
            check("dry run of a registered draft: notice, exit 0", issue_submit.main([str(p2)]) == 0)
            check("submit of a registered draft refused, exit 1",
                  issue_submit.main([str(p2), "--submit"]) == 1)
            check("grant for a registered draft refused",
                  grant(p2) == 1 and not approval_path(mid2).exists())

            # marker exactly once and after the JSON block (S1-7)
            block = "```json disclosure\n{\"id\": \"m-01\"}\n```\n"
            for name, body, expect in (
                    ("ok", "# n\n\n" + block + "\n<!-- TEXT -->\nhello\n", "hello"),
                    ("before", "# n\n<!-- TEXT -->\nevil\n\n" + block + "\n<!-- TEXT -->\nhello\n", None),
                    ("only before", "<!-- TEXT -->\nevil\n" + block, None),
                    ("in json", "```json disclosure\n{\"id\": \"<!-- TEXT -->\"}\n```\nno text\n", None),
                    ("twice after", block + "<!-- TEXT -->\na\n<!-- TEXT -->\nb\n", None),
                    ("missing", block + "no marker\n", None)):
                mp = Path(td) / f"marker-{name.replace(' ', '-')}.md"
                write_text(mp, body)
                try:
                    got = read_draft(mp)[1]
                except DisclosureError:
                    got = None
                check(f"marker: {name}", got == expect)

            # approval is consumed BEFORE the external call; the check record stays (S1-5)
            old_checks = _common.CHECKS
            _common.CHECKS = Path(td) / "checks"
            try:
                raw_x = b"x"
                _common.write_approval("selftest-send", raw_x, "issue", "t")
                write_text(_common.check_path("selftest-send"), "sha256=0\n")
                with _submit.sending("selftest-send"):
                    check("approval consumed before the call", not approval_path("selftest-send").exists())
                try:
                    with _submit.sending("selftest-send"):
                        raise DisclosureError("simulated post failure")
                except DisclosureError:
                    pass
                check("check record survives sending()", _common.check_path("selftest-send").exists())
            finally:
                _common.CHECKS = old_checks

            # register lock: second writer refused while locked, stale lock taken over (S1-9)
            import os
            import time
            old_wait = _common.LOCK_WAIT_SECONDS
            _common.LOCK_WAIT_SECONDS = 0.3
            lock = _common.REGISTER_PRIVATE.with_name("register.lock")
            lock.parent.mkdir(parents=True, exist_ok=True)
            try:
                with _common.register_lock():
                    check("lock file exists while held", lock.exists())
                    with _common.register_lock():
                        pass                                   # re-entrant
                    check("lock still held after the inner block", lock.exists())
                check("lock released", not lock.exists())
                lock.write_text("pid=0\n", encoding="ascii")
                try:
                    with _common.register_lock():
                        check("locked register refused", False)
                except DisclosureError:
                    check("locked register refused", True)
                old_time = time.time() - _common.LOCK_STALE_SECONDS - 60
                os.utime(lock, (old_time, old_time))
                with _common.register_lock():
                    check("stale lock taken over", True)
                _common.save_register([{"id": "z-01", "channel": "issue"}, {"id": "z-02", "channel": "email"}])
                check("save_register writes both parts atomically",
                      [e["id"] for e in _common.load_register()] == ["z-01", "z-02"]
                      and not _common.REGISTER.with_name("register.json.tmp").exists()
                      and not lock.exists())
            finally:
                _common.LOCK_WAIT_SECONDS = old_wait
                if lock.exists():
                    lock.unlink()
        finally:
            _common.APPROVALS, _submit.FETCH_BLOB = old_approvals, old_fetch
            _common.REGISTER, _common.REGISTER_PRIVATE = old_reg
            for k, v in old_switches.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    out(f"approval self-test (policy check): {ok}/{total} OK")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
