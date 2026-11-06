#!/usr/bin/env python3
"""Codex cross-check of a disclosure text before approval and submission.

NOT an audit. Codex gets exactly the text that would go out (head fields + text after the
marker) and checks every factual claim in it against the upstream source at the referenced
commit: files, line numbers, permalinks, function and option names, described behaviour,
affected versions, reproduction steps, the impact rating. It does not search for new findings.

Only active if the project's .env (or the environment) switches it on:

    disclosure_codex_check=on            # off/absent = no cross-check required
    disclosure_codex_model=gpt-6.1-sol   # default
    disclosure_codex_effort=medium       # default

When it is on, approval.py grant and every submit tool (issue_submit.py, advisory_submit.py,
mail_report.py send) refuse unless there is a record private/disclosures/checks/<id>.check
for exactly this draft hash, with the configured model/effort, and the Codex output ends with
"CHECK: CONFIRMED". Any change to the draft invalidates the check (same as the approval).

  python tools/disclosures/codex_check.py run      <draft.md> --source quarantine/<name>
  python tools/disclosures/codex_check.py finding  <draft.md> --source quarantine/<name>
  python tools/disclosures/codex_check.py exposure <draft.md> --source quarantine/<name>
  python tools/disclosures/codex_check.py status   <draft.md>
  python tools/disclosures/codex_check.py config
  python tools/disclosures/codex_check.py --self-test

Scope and further switches of the text check:

    disclosure_codex_check=on|critical|off      # critical = only severity_class critical
    disclosure_codex_channels=issue,comment,advisory,email   # default: all four
    disclosure_codex_timeout=1500

Two further gates check the FINDING itself (claudex integration), each with its own switch
(off | critical | all), model and effort; without a model in the .env the role configuration of
claudex-loop is asked (claudex_loop_dir -> scripts/claudex_roles.py --spec <role>), else the
default applies:

    finding   claudex_finding_check / _model / _effort     role code-review
              Is the finding real at the referenced commit, are the preconditions, the
              severity class and the rating (CVSS/CWE) supported by the code, is it by design
              per the policy fields? Last line FINDING: CONFIRMED | FINDING: NOT CONFIRMED |
              FINDING: SEVERITY WRONG. Only CONFIRMED passes.
    exposure  claudex_exposure_check / _model / _effort    role exposure-review
              Is the affected code reachable from outside the machine (network listener,
              webhook, untrusted input from another party) and by whom? Last line
              EXPOSURE: UNSAFE (reachable) | EXPOSURE: SAFE. Blocks if it contradicts the
              draft field "exposure" (network|local), and a critical finding with SAFE needs
              "exposure_override": "<reason>".

Both records (private/disclosures/checks/<id>.finding.check, <id>.exposure.check) are bound
to a digest of the finding fields (finding, severity, rating, upstream_ref, exposure, repo,
forge) - not to the wording: correcting the text needs a new text check only.

--source is a clone under quarantine/ checked out (detached) on a commit whose SHA appears in
the draft's "upstream_ref" (tools/quarantine_clone.py creates it, also for Gitea, GitLab and
other git servers). The prompt is written to .claudex-tmp/disclosures/<id>/ and only
contains the outgoing text and the finding fields - the internal part of the draft is not sent. The Codex output is
stored under private/disclosures/checks/ (it may quote confidential drafts).

Runs through tools/codex_ro.py (read-only wrapper), one run at a time, never in parallel.
Exit 0 CHECK: CONFIRMED / FINDING: CONFIRMED / an exposure verdict consistent with the draft
(or the check is switched off), 1 CORRECTIONS NEEDED, NOT CONFIRMED, SEVERITY WRONG, an
inconsistent exposure verdict or no valid result, 2 operator error, 3 Codex could not execute commands (the check did not happen),
4 Codex usage limit reached (nothing recorded; run again after the time Codex names).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common  # noqa: E402
from _common import (CHECK_FAIL, CHECK_PASS, CODEX_CHECK_CHANNELS, FORMS, ROOT, DisclosureError,  # noqa: E402
                     audit_config, check_codex, check_form, codex_check_config, err, finding_digest,
                     form_config, last_line, out, read_draft, scope_applies, sha256_bytes, write_check,
                     write_form_check, write_text)
import forge as forges  # noqa: E402

HEAD_FIELDS = ("title", "summary", "subject", "cvss_vector_string", "severity", "cwe_ids",
               "vulnerabilities", "repo", "issue", "to")
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
CODEX_TIMEOUT = 1500

PROMPT = """\
Form: **Disclosure cross-check** (NOT an audit). Role and off-limits list: AGENTS.md.

You check a vulnerability/bug report that we are about to send to the maintainers of
{repo}. Our reputation depends on every statement in it being correct. Your only job is to
verify the statements that are already in the text. Do NOT look for new findings, do NOT
review the rest of the code base, do NOT suggest additional issues.

Source tree (read-only, upstream code at commit {sha}): `{source}`
Permalinks in the text of the form {permalink} map to
`{source}/<path>` lines a-b if <sha> is {sha}; for any other SHA say so.
You have no network: claims about issues, PRs/merge requests, advisories or releases on the
code host (numbers, states, titles) are NOT VERIFIABLE - list them, they do not block.

Channel: {channel}. Severity class we assigned: {severity_class}.

Head fields that go out with the text:

```json
{head}
```

Text that goes out exactly as written:

---8<---
{text}
---8<---

Procedure:

1. Split the text (and the head fields) into individual factual claims: file and line
   references, permalinks, function/variable/option/command names, described code
   behaviour, conditions and triggers, affected versions/range, reproduction steps,
   impact and rating (CVSS vector components, CWE), statements about existing fixes,
   and the suggested fix where it names existing code.
2. Check each claim against the source tree by reading the cited code (rg, git show,
   reading files). Follow call paths only as far as needed to confirm or refute that claim.
3. Classify each claim: CONFIRMED, WRONG (contradicted by the code), OVERSTATED (true
   core, but the text claims more than the code supports - e.g. a weaker precondition, a
   higher impact, "always" where it is conditional), or NOT VERIFIABLE (offline/out of
   the tree; say why).
4. Also flag: line ranges that are off, a CVSS vector or CWE that does not match the
   described behaviour, reproduction steps that would not work as written, and wording a
   maintainer could fairly call wrong or misleading.

Result (English, concise):

- Table: # | claim (short) | location checked (file:line) | CONFIRMED/WRONG/OVERSTATED/NOT VERIFIABLE | note
- For every WRONG or OVERSTATED item: the exact sentence from the text and a corrected
  wording that is supported by the code.
- Coverage note: what you did not open.
- Last line exactly one of:
  `{passed}` - no claim is WRONG or OVERSTATED
  `{failed}` - at least one claim is WRONG or OVERSTATED
"""


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(p)


def source_sha(source: Path) -> str:
    r = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise DisclosureError(f"--source {source} is not a git checkout")
    return r.stdout.strip()


def check_source(meta, source: Path) -> str:
    quarantine = (ROOT / "quarantine").resolve()
    src = source.resolve()
    if src != quarantine and quarantine not in src.parents:
        raise DisclosureError("--source must be a clone under quarantine/ (rule 2 of CLAUDE.md)")
    if not src.is_dir():
        raise DisclosureError(f"--source {source} does not exist - clone it first "
                              "(no submodules, GIT_LFS_SKIP_SMUDGE=1, git checkout --detach <sha>)")
    sha = source_sha(src)
    refs = SHA_RE.findall(str(meta.get("upstream_ref", "")))
    if sha not in refs:
        raise DisclosureError(f"--source is on {sha[:12]}, the draft's upstream_ref names "
                              f"{', '.join(r[:12] for r in refs) or 'no full SHA'} - check out one of them")
    return sha


def permalink_hint(meta) -> str:
    try:
        return forges.forge_of(meta).permalink_hint(meta.get("repo") or "<owner>/<name>")
    except DisclosureError:
        return f"<code host>/{meta.get('repo')}/blob/<sha>/<path>#L<a>-L<b>"


def build_prompt(meta, text: str, source: Path, sha: str) -> str:
    head = {k: meta[k] for k in HEAD_FIELDS if meta.get(k) not in (None, "", [])}
    return PROMPT.format(repo=forges.target_of(meta) or "-", sha=sha, source=_rel(source),
                         permalink=permalink_hint(meta),
                         channel=meta.get("channel"), severity_class=meta.get("severity_class"),
                         head=json.dumps(head, indent=2, ensure_ascii=False), text=text,
                         passed=CHECK_PASS, failed=CHECK_FAIL)


def thread_id_from(err_file: Path) -> str:
    try:
        m = re.search(r"session id:\s*([0-9a-f-]{36})", err_file.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""
    return m.group(1) if m else ""


QUOTA_RE = re.compile(r"usage limit[^\"]*?try again at ([^\"]+?[AP]M)", re.I)


def quota_hit(out_file: Path):
    """(hit, time) from the Codex event stream next to the answer file."""
    stream = out_file.with_name(out_file.name + ".stream.json")
    try:
        data = stream.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, ""
    m = QUOTA_RE.search(data)
    return (True, m.group(1).strip()) if m else ("usage limit" in data.lower(), "")


def stream_error(out_file: Path) -> str:
    """Last error message Codex reported in its event stream (API errors, unknown model)."""
    stream = out_file.with_name(out_file.name + ".stream.json")
    try:
        lines = stream.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        msg = ev.get("message") or (ev.get("error") or {}).get("message") if isinstance(ev, dict) else ""
        if ev.get("type") in ("error", "turn.failed") and msg:
            try:
                msg = json.loads(msg).get("error", {}).get("message", msg)
            except (ValueError, AttributeError):
                pass
            return str(msg)[:300]
    return ""


def run(draft: Path, source: Path, runner=None) -> int:
    cfg = codex_check_config()
    meta, text, raw = read_draft(draft)
    if not cfg["enabled"]:
        out("Codex cross-check is switched off (disclosure_codex_check in .env) - nothing to do.")
        return 0
    if meta.get("channel") not in cfg["channels"]:
        out(f"channel {meta.get('channel')!r} is not checked (disclosure_codex_channels) - no cross-check needed.")
        return 0
    if not scope_applies(cfg["scope"], meta):
        out(f"disclosure_codex_check={cfg['scope']}: {meta.get('severity_class')} finding - no cross-check needed.")
        return 0
    if not meta.get("id"):
        raise DisclosureError("draft: field 'id' missing")
    sha = check_source(meta, source)
    digest = sha256_bytes(raw)
    work = ROOT / ".claudex-tmp" / "disclosures" / meta["id"]
    prompt_file = work / f"check-{digest[:12]}.txt"
    err_file = work / f"check-{digest[:12]}-err.txt"
    record = _common.record_of(meta, draft)
    out_file = _common.checks_dir(record) / f"{meta['id']}-{digest[:12]}.out.md"
    write_text(prompt_file, build_prompt(meta, text, source, sha))
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out(f"Codex cross-check {meta['id']} ({cfg['model']}/{cfg['effort']}) against {sha[:12]} ...")
    rc, answer = execute(cfg, prompt_file, out_file, err_file, runner, cfg.get("timeout", CODEX_TIMEOUT))
    if rc is not None:
        return rc
    verdict = last_line(answer)
    if verdict not in (CHECK_PASS, CHECK_FAIL):
        out(f"ERROR: Codex output has no valid last line (got {verdict[:60]!r}) - see {_rel(out_file)} "
            f"and {_rel(err_file)}; nothing recorded")
        return 1
    p = write_check(meta["id"], raw, cfg, verdict, out_file, thread_id_from(err_file), record)
    out(f"{verdict}  (record {_rel(p)}, output {_rel(out_file)})")
    if verdict == CHECK_FAIL:
        out("Read the output, correct the draft, run the cross-check again (new text = new hash).")
        return 1
    return 0


def execute(cfg, prompt_file: Path, out_file: Path, err_file: Path, runner=None, timeout=CODEX_TIMEOUT):
    """One read-only Codex run via tools/codex_ro.py. (exit code to return, None) on failure,
    (None, answer) on success. Nothing is recorded here."""
    cmd = [sys.executable, str(ROOT / "tools" / "codex_ro.py"), "--model", cfg["model"],
           "--effort", cfg["effort"], "--prompt-file", _rel(prompt_file), "--out-file", _rel(out_file),
           "--err-file", _rel(err_file), "--timeout", str(timeout)]
    rc = (runner or (lambda c: subprocess.run(c, cwd=str(ROOT)).returncode))(cmd)
    if rc != 0:
        # A usage limit can also surface as exit 3 (the turn failed before any command ran).
        hit, when = quota_hit(out_file)
        if hit:
            out(f"ERROR: Codex usage limit reached{' - try again at ' + when if when else ''}; nothing recorded")
            return 4, ""
    if rc == 3:
        reason = stream_error(out_file)
        out("ERROR: Codex could not execute any command (exit 3) - the check did not happen, nothing recorded"
            + (f"\n  Codex reported: {reason}" if reason else ""))
        return 3, ""
    if rc != 0:
        out(f"ERROR: codex_ro.py exit {rc} - see {_rel(err_file)}; nothing recorded")
        return 2, ""
    return None, (out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else "")


FINDING_FORM_FIELDS = ("finding", "severity_class", "severity_reason", "upstream_ref", "cvss_vector_string",
                       "severity", "cwe_ids", "vulnerabilities", "exposure", "exposure_override")
POLICY_FIELDS = ("versions", "scope", "result")

FINDING_PROMPT = """\
Form: **Finding validation** (NOT an audit, NOT a text review). Role and off-limits list: AGENTS.md.

Before we report a finding to the maintainers of {repo}, decide whether the FINDING is real
and correctly rated. Do NOT look for other findings, do NOT review the rest of the code base.

Source tree (read-only, upstream code at commit {sha}): `{source}`
Permalinks of the form {permalink} map to `{source}/<path>`.
You have no network.

Finding fields of our draft:

```json
{fields}
```

Assessment of the upstream security policy we recorded (scope, supported versions):

```json
{policy}
```

Description that goes out (it names the files, lines and the behaviour):

---8<---
{text}
---8<---

Procedure:

1. Locate the code the finding is about and read it; follow the data/call path from the
   entry point to the affected spot far enough to decide.
2. Decide: does the described behaviour exist at this commit? Which preconditions does an
   attacker or user need (configuration, local access, authentication, user interaction)?
   Is there a guard elsewhere that prevents it (validation, sandbox, permission check)?
3. Rate: does the severity class ({severity_class}) and the given CVSS/CWE match what the
   code supports? Is it documented as intended behaviour or out of scope per the policy?
4. Keep the reasoning to the code; quote file:line for every statement.

Result (English, concise):

- Reproduction path: entry point -> ... -> affected spot (file:line each)
- Preconditions found in the code; guards found (or "none found")
- Rating: severity class, CVSS components and CWE you consider supported, with reasons
- Coverage note: what you did not open
- Last line exactly one of:
  `FINDING: CONFIRMED` - real at this commit, rating supported
  `FINDING: SEVERITY WRONG` - real, but the severity class or the rating is not supported
  `FINDING: NOT CONFIRMED` - not real as described (guard, dead code, wrong reading, by design)
"""

EXPOSURE_PROMPT = """\
Form: **Exposure pass** for one finding (claudex-loop role exposure-review; NOT an audit).
Role and off-limits list: AGENTS.md.

Decide whether the code affected by this finding in {repo} is reachable from OUTSIDE the
machine it runs on, and by whom. Do NOT look for other findings.

Source tree (read-only, upstream code at commit {sha}): `{source}`
You have no network.

Finding fields of our draft:

```json
{fields}
```

Description:

---8<---
{text}
---8<---

Procedure:

1. Identify the affected component and every way input reaches it: network listeners
   (ports, bind addresses, default config), HTTP routes, webhooks, proxies/tunnels, files or
   repositories from other parties (clone, download, package), messages from chat/mail
   integrations, CI inputs, environment of other users.
2. For each path: who can send that input (anyone on the internet, the LAN, an authenticated
   user, only the local user), and what the default configuration does (bound to localhost?
   off by default? auth required?).
3. Local-only means: an attacker needs prior code execution or write access on the machine.

Result (English, concise):

- Table: path | input source | who can use it | default config | file:line
- Conclusion in two sentences
- Last line exactly one of:
  `EXPOSURE: UNSAFE` - reachable by a party without prior local access (network, foreign content)
  `EXPOSURE: SAFE` - only reachable with prior local access or by the local user themselves
"""


def build_form_prompt(form: str, meta, text: str, source: Path, sha: str) -> str:
    fields = {k: meta[k] for k in FINDING_FORM_FIELDS if meta.get(k) not in (None, "", [])}
    pol = meta.get("policy") if isinstance(meta.get("policy"), dict) else {}
    template = FINDING_PROMPT if form == "finding" else EXPOSURE_PROMPT
    return template.format(repo=forges.target_of(meta) or "-", sha=sha, source=_rel(source),
                           permalink=permalink_hint(meta), severity_class=meta.get("severity_class"),
                           fields=json.dumps(fields, indent=2, ensure_ascii=False),
                           policy=json.dumps({k: pol.get(k) for k in POLICY_FIELDS if pol.get(k)}, indent=2,
                                             ensure_ascii=False), text=text)


def run_form(form: str, draft: Path, source: Path, runner=None) -> int:
    """Finding validation or exposure pass (see module docstring)."""
    cfg = form_config(form)
    label = FORMS[form]["label"]
    meta, text, _raw = read_draft(draft)
    if not cfg["enabled"]:
        out(f"Codex {label} is switched off ({FORMS[form]['switch']} in .env) - nothing to do.")
        return 0
    if meta.get("channel") not in CODEX_CHECK_CHANNELS:
        out(f"channel {meta.get('channel')!r} is not a report - no {label} needed.")
        return 0
    if not scope_applies(cfg["scope"], meta):
        out(f"{FORMS[form]['switch']}={cfg['scope']}: {meta.get('severity_class')} finding - no {label} needed.")
        return 0
    if not meta.get("id"):
        raise DisclosureError("draft: field 'id' missing")
    sha = check_source(meta, source)
    digest = finding_digest(meta)
    work = ROOT / ".claudex-tmp" / "disclosures" / meta["id"]
    prompt_file = work / f"{form}-{digest[:12]}.txt"
    err_file = work / f"{form}-{digest[:12]}-err.txt"
    record = _common.record_of(meta, draft)
    out_file = _common.checks_dir(record) / f"{meta['id']}-{form}-{digest[:12]}.out.md"
    write_text(prompt_file, build_form_prompt(form, meta, text, source, sha))
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out(f"Codex {label} {meta['id']} ({cfg['model']}/{cfg['effort']}) against {sha[:12]} ...")
    rc, answer = execute(cfg, prompt_file, out_file, err_file, runner, codex_check_config()["timeout"])
    if rc is not None:
        return rc
    verdict = last_line(answer)
    if verdict not in FORMS[form]["verdicts"]:
        out(f"ERROR: Codex output has no valid last line (got {verdict[:60]!r}) - see {_rel(out_file)} "
            f"and {_rel(err_file)}; nothing recorded")
        return 1
    p = write_form_check(meta, form, cfg, verdict, out_file, sha, thread_id_from(err_file), record)
    ok, reason = check_form(meta, form, cfg)
    out(f"{verdict}  (record {_rel(p)}, output {_rel(out_file)})")
    if not ok:
        out(f"BLOCKED: {reason}")
        return 1
    return 0


def status(draft: Path) -> int:
    meta, _text, raw = read_draft(draft)
    cfg = codex_check_config()
    ok, reason = check_codex(meta, raw, cfg)
    out(f"text check: {cfg['scope']} ({cfg['model']}/{cfg['effort']}, channels {','.join(cfg['channels'])})")
    out(f"  {meta.get('id')}: {'OK' if ok else 'BLOCKED'} - {reason}")
    all_ok = ok
    for form in FORMS:
        fc = form_config(form)
        ok_f, reason_f = check_form(meta, form, fc)
        out(f"{FORMS[form]['label']}: {fc['scope']} ({fc['model']}/{fc['effort']})")
        out(f"  {meta.get('id')}: {'OK' if ok_f else 'BLOCKED'} - {reason_f}")
        all_ok = all_ok and ok_f
    return 0 if all_ok else 1


def show_config() -> int:
    cfg = codex_check_config()
    out(f"disclosure_codex_check: {cfg['scope']}  model/effort {cfg['model']}/{cfg['effort']}  "
        f"channels {','.join(cfg['channels'])}  timeout {cfg['timeout']} s")
    for form in FORMS:
        fc = form_config(form)
        out(f"{FORMS[form]['switch']}: {fc['scope']}  model/effort {fc['model']}/{fc['effort']}  "
            f"(role {FORMS[form]['role']})")
    ac = audit_config()
    out(f"claudex_audit_mode: {ac['mode']}  model/effort {ac['model']}/{ac['effort']}  "
        f"claudex_loop_dir {'set' if ac['claudex_loop_dir'] else '-'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Codex cross-check of a disclosure text")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("run", "finding", "exposure"):
        r = sub.add_parser(name)
        r.add_argument("draft")
        r.add_argument("--source", required=True, help="clone under quarantine/ on the referenced commit")
    s = sub.add_parser("status")
    s.add_argument("draft")
    sub.add_parser("config")
    a = ap.parse_args(argv)
    if a.self_test:
        return max(self_test(), self_test_forms())
    try:
        if a.cmd == "run":
            return run(Path(a.draft), Path(a.source))
        if a.cmd in FORMS:
            return run_form(a.cmd, Path(a.draft), Path(a.source))
        if a.cmd == "status":
            return status(Path(a.draft))
        if a.cmd == "config":
            return show_config()
        ap.print_help()
        return 2
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 2


# --------------------------------------------------------------------------- #
# Self-test (no network, no Codex): switch, record binding, gate in approval/submit
# --------------------------------------------------------------------------- #

def self_test() -> int:
    import os
    import tempfile

    import approval
    import _submit

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    keys = _common.CODEX_CHECK_KEYS
    saved_env = {k: os.environ.pop(k, None) for k in keys}
    saved = (_common.ROOT, _common.CHECKS, _common.ENV_FILE, _common.APPROVALS, _common.REGISTER,
             _common.REGISTER_PRIVATE, _submit.FETCH_BLOB)
    g = globals()
    saved_root = g["ROOT"]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _common.ROOT = g["ROOT"] = root
        _common.CHECKS = root / "private" / "disclosures" / "checks"
        _common.ENV_FILE = root / ".env"
        _common.APPROVALS = root / "private" / "disclosures" / "approvals"
        _common.REGISTER = root / "register.json"
        _common.REGISTER_PRIVATE = root / "register.private.json"
        blob = "a" * 40
        _submit.FETCH_BLOB = lambda repo, path: blob if path == "SECURITY.md" else None
        try:
            # Switch
            check("switch off without .env", codex_check_config()["enabled"] is False)
            write_text(_common.ENV_FILE, "# x\ndisclosure_codex_check=on   # comment\n")
            cfg = codex_check_config()
            check("switch on from .env", cfg["enabled"] is True)
            check("default model/effort", (cfg["model"], cfg["effort"]) == ("gpt-6.1-sol", "medium"))
            os.environ["disclosure_codex_check"] = "off"
            check("environment wins over .env", codex_check_config()["enabled"] is False)
            del os.environ["disclosure_codex_check"]

            # Draft and quarantine clone stand-in
            sha = "c" * 40
            pol = {"blob_sha": blob, "path": "SECURITY.md", "checked_at": "2026-10-10", "versions": "v",
                   "channel": "issue ok", "scope": "in scope", "deadlines": "none",
                   "required_content": {}, "response_days": None, "result": "report"}
            meta = {"id": "selftest-cc", "channel": "issue", "repo": "acme/tool", "title": "Parser bug",
                    "finding": "f", "severity_class": "non-critical", "severity_reason": "bug",
                    "upstream_ref": f"main@{sha}", "policy": pol}
            draft = root / "d.md"

            def write_draft(body):
                write_text(draft, "# internal\n\n```json disclosure\n" + json.dumps(meta, indent=2)
                           + "\n```\n\n<!-- TEXT -->\n" + body + "\n")
                return draft.read_bytes()

            raw = write_draft("**Summary**\n\nThe parser drops a newline (`p.py` L3).")
            check("no record -> blocked", check_codex(meta, raw)[0] is False)
            check("reaction needs no check", check_codex({**meta, "channel": "reaction"}, raw)[0] is True)

            quarantine = root / "quarantine" / "tool"
            quarantine.mkdir(parents=True)
            g_sha = globals()["source_sha"]
            globals()["source_sha"] = lambda s: sha
            try:
                def fake(verdict, rc=0):
                    def runner(cmd):
                        if verdict is not None:
                            o = root / cmd[cmd.index("--out-file") + 1]
                            write_text(o, f"| 1 | ... | p.py:3 | CONFIRMED | |\n\n{verdict}\n")
                        return rc
                    return runner

                check("source outside quarantine refused",
                      _expect_error(lambda: check_source(meta, root / "elsewhere")))
                check("exit 3 -> nothing recorded",
                      run(draft, quarantine, fake(None, 3)) == 3 and not _common.read_check(meta["id"]))
                def quota(cmd):
                    o = root / cmd[cmd.index("--out-file") + 1]
                    write_text(o.with_name(o.name + ".stream.json"),
                               '{"type": "error", "message": "You hit your usage limit. '
                               'Visit x or try again at 9:02 PM."}')
                    return 1
                check("usage limit -> exit 4, nothing recorded",
                      run(draft, quarantine, quota) == 4 and not _common.read_check(meta["id"]))

                def quota3(cmd):
                    o = root / cmd[cmd.index("--out-file") + 1]
                    write_text(o.with_name(o.name + ".stream.json"),
                               '{"type":"error","message":"You hit your usage limit. Visit x or '
                               'try again at Oct 11th, 2026 2:15 AM."}')
                    return 3
                write_text(root / "e.out.md.stream.json",
                           '{"type":"turn.failed","error":{"message":"{\\"type\\":\\"error\\",\\"error\\":'
                           '{\\"message\\":\\"model is not supported\\"}}"}}')
                check("API error is surfaced", stream_error(root / "e.out.md") == "model is not supported")
                check("usage limit with exit 3 -> exit 4",
                      run(draft, quarantine, quota3) == 4)
                m = QUOTA_RE.search('usage limit. Visit x or try again at Oct 11th, 2026 2:15 AM."}')
                check("quota time with date", bool(m) and m.group(1) == "Oct 11th, 2026 2:15 AM")
                check("no verdict line -> nothing recorded",
                      run(draft, quarantine, fake("looks fine")) == 1 and not _common.read_check(meta["id"]))
                check("CORRECTIONS NEEDED -> exit 1", run(draft, quarantine, fake(CHECK_FAIL)) == 1)
                check("CORRECTIONS NEEDED blocks", check_codex(meta, raw)[0] is False)
                check("CONFIRMED -> exit 0", run(draft, quarantine, fake(CHECK_PASS)) == 0)
                check("CONFIRMED passes", check_codex(meta, raw) == (True, "ok"))
                check("approval grant passes",
                      approval.main(["grant", str(draft), "--action", "issue", "--note", "t"]) == 0)
                rec = _common.read_check(meta["id"])
                out_path = root / rec["output"]
                write_text(out_path, out_path.read_text(encoding="utf-8") + "edited\n")
                check("edited Codex output blocks", "changed" in check_codex(meta, raw)[1])
                run(draft, quarantine, fake(CHECK_PASS))
                write_text(_common.ENV_FILE, "disclosure_codex_check=on\ndisclosure_codex_effort=high\n")
                check("other effort required -> blocked", "required" in check_codex(meta, raw)[1])
                write_text(_common.ENV_FILE, "disclosure_codex_check=on\n")
                raw2 = write_draft("**Summary**\n\nThe parser drops two newlines.")
                check("changed draft -> blocked", "hash differs" in check_codex(meta, raw2)[1])
                check("grant refused without a current check (exit 1)",
                      approval.main(["grant", str(draft), "--action", "issue", "--note", "t"]) == 1)
                import issue_submit

                def no_network(*_a, **_k):
                    raise AssertionError("self-test must not reach GitHub")
                saved_gh = (_common.gh_post, _common.gh_logged_in)
                _common.gh_post = _common.gh_logged_in = no_network
                try:
                    check("submit refused without a current check",
                          issue_submit.main([str(draft), "--submit"]) == 1)
                finally:
                    _common.gh_post, _common.gh_logged_in = saved_gh
                write_text(_common.ENV_FILE, "disclosure_codex_check=off\n")
                check("switch off -> no check needed", check_codex(meta, raw2)[0] is True)
            finally:
                globals()["source_sha"] = g_sha
        finally:
            (_common.ROOT, _common.CHECKS, _common.ENV_FILE, _common.APPROVALS, _common.REGISTER,
             _common.REGISTER_PRIVATE, _submit.FETCH_BLOB) = saved
            g["ROOT"] = saved_root
            for k, v in saved_env.items():
                if v is not None:
                    os.environ[k] = v
    out(f"codex_check self-test: {ok}/{total} OK")
    return 0 if ok == total else 1


def self_test_forms() -> int:
    """Finding validation and exposure pass: switches, scope, digest binding, gates."""
    import os
    import tempfile

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    keys = _common.CODEX_CHECK_KEYS + _common.CLAUDEX_KEYS
    saved_env = {k: os.environ.pop(k, None) for k in keys}
    saved = (_common.ROOT, _common.CHECKS, _common.ENV_FILE)
    g = globals()
    saved_root, saved_sha = g["ROOT"], g["source_sha"]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _common.ROOT = g["ROOT"] = root
        _common.CHECKS = root / "private" / "disclosures" / "checks"
        _common.ENV_FILE = root / ".env"
        sha = "d" * 40
        g["source_sha"] = lambda s: sha
        try:
            check("forms off by default", not form_config("finding")["enabled"] and not form_config("exposure")["enabled"])
            write_text(_common.ENV_FILE, "claudex_finding_check=critical\nclaudex_exposure_check=all\n"
                                         "claudex_exposure_model=gpt-6-sol\ndisclosure_codex_check=critical\n"
                                         "disclosure_codex_channels=issue,advisory\n")
            fc, ec, tc = form_config("finding"), form_config("exposure"), codex_check_config()
            check("finding scope critical, default model", (fc["scope"], fc["model"], fc["effort"])
                  == ("critical", "gpt-6.1-sol", "medium"))
            check("exposure model from .env", (ec["scope"], ec["model"]) == ("all", "gpt-6-sol"))
            check("text check scope + channels", tc["scope"] == "critical" and tc["channels"] == ("issue", "advisory"))
            check("bad switch value refused", _expect_error(lambda: _common._scope("maybe")))
            meta = {"id": "selftest-fv", "channel": "issue", "repo": "g/s/n", "forge": "corp", "title": "t",
                    "finding": "path traversal in export", "severity_class": "critical", "severity_reason": "r",
                    "upstream_ref": f"main@{sha}", "exposure": "network"}
            draft = root / "d.md"

            def write_draft(m, body="**Summary** export joins a user path (`x.py` L3)."):
                write_text(draft, "# internal\n\n```json disclosure\n" + json.dumps(m, indent=2)
                           + "\n```\n\n<!-- TEXT -->\n" + body + "\n")
                return draft.read_bytes()

            raw = write_draft(meta)
            check("critical: finding check required", check_form(meta, "finding")[0] is False)
            check("non-critical: finding check not required",
                  check_form({**meta, "severity_class": "non-critical"}, "finding")[0] is True)
            check("text check off for comment channel (channels)",
                  check_codex({**meta, "channel": "comment"}, raw, tc)[0] is True)
            check("text check off for non-critical (scope)",
                  check_codex({**meta, "severity_class": "non-critical"}, raw, tc)[0] is True)
            q = root / "quarantine" / "tool"
            q.mkdir(parents=True)
            prompts = []

            def fake(verdict, rc=0):
                def runner(cmd):
                    prompts.append((root / cmd[cmd.index("--prompt-file") + 1]).read_text(encoding="utf-8"))
                    if verdict is not None:
                        write_text(root / cmd[cmd.index("--out-file") + 1], f"- path ...\n\n{verdict}\n")
                    return rc
                return runner

            check("finding: invalid last line -> nothing recorded",
                  run_form("finding", draft, q, fake("looks real")) == 1
                  and not _common.read_form_check(meta["id"], "finding"))
            check("finding: prompt carries fields, not the internal part",
                  "path traversal in export" in prompts[-1] and "# internal" not in prompts[-1])
            check("finding: NOT CONFIRMED -> exit 1, blocks",
                  run_form("finding", draft, q, fake("FINDING: NOT CONFIRMED")) == 1
                  and "NOT CONFIRMED" in check_form(meta, "finding")[1])
            check("finding: CONFIRMED -> exit 0, passes",
                  run_form("finding", draft, q, fake("FINDING: CONFIRMED")) == 0 and check_form(meta, "finding")[0])
            write_draft(meta, "**Summary** reworded text only.")
            check("finding: text change keeps the validation", check_form(meta, "finding")[0])
            m2 = {**meta, "severity_reason": "other"}
            check("finding: changed finding field invalidates", "other finding fields" in check_form(m2, "finding")[1])
            check("exposure: SAFE contradicts exposure=network",
                  run_form("exposure", draft, q, fake("EXPOSURE: SAFE")) == 1
                  and "exposure='network'" in check_form(meta, "exposure")[1])
            m3 = {**meta, "exposure": "local"}
            write_draft(m3)
            run_form("exposure", draft, q, fake("EXPOSURE: SAFE"))
            check("exposure: critical + SAFE needs an override", "exposure_override" in check_form(m3, "exposure")[1])
            m4 = {**m3, "exposure_override": "local privilege boundary on shared hosts"}
            write_draft(m4)
            run_form("exposure", draft, q, fake("EXPOSURE: SAFE"))
            check("exposure: override passes", check_form(m4, "exposure")[0])
            write_draft(meta)
            check("exposure: UNSAFE consistent with network", run_form("exposure", draft, q, fake("EXPOSURE: UNSAFE")) == 0)
            rec = _common.read_form_check(meta["id"], "exposure")
            o = root / rec["output"]
            write_text(o, o.read_text(encoding="utf-8") + "x\n")
            check("exposure: edited output blocks", "changed" in check_form(meta, "exposure")[1])
            check("check_claudex lists three gates", [x[1] for x in _common.check_claudex(meta, draft.read_bytes())]
                  == ["text check", "finding validation", "exposure pass"])
            check("quota -> exit 4, nothing recorded", run_form("finding", draft, q, lambda c: (
                write_text(root / (c[c.index("--out-file") + 1] + ".stream.json"),
                           '{"type":"error","message":"You hit your usage limit. try again at 2:15 AM."}'), 1)[1]) == 4)
            write_text(_common.ENV_FILE, "x=1\n")
            check("audit mode default form", audit_config()["mode"] == "form")
            write_text(_common.ENV_FILE, "claudex_audit_mode=both\n")
            check("audit mode both", audit_config()["mode"] == "both")
            write_text(_common.ENV_FILE, "claudex_audit_mode=sometimes\n")
            check("audit mode: bad value refused", _expect_error(audit_config))
            write_text(_common.ENV_FILE, "claudex_initial_audit=codex\n")
            check("old key claudex_initial_audit refused with a hint", _expect_error(audit_config))
            check("permalink hint without forge config", "blob" in permalink_hint({"repo": "o/n"}))
        finally:
            (_common.ROOT, _common.CHECKS, _common.ENV_FILE) = saved
            g["ROOT"], g["source_sha"] = saved_root, saved_sha
            for k, v in saved_env.items():
                if v is not None:
                    os.environ[k] = v
    out(f"codex_check self-test (finding/exposure): {ok}/{total} OK")
    return 0 if ok == total else 1


def _expect_error(fn) -> bool:
    try:
        fn()
    except DisclosureError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
