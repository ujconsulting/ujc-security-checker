#!/usr/bin/env python3
"""Create a public issue (or a comment on an existing issue) from a draft.

The default is the dry run: shows title and text exactly as they would be sent,
runs the leak scan and prints the SHA-256. Sent only with --submit AND a valid
hash-bound approval (private/disclosures/approvals/<id>.approval, see approval.py).
The approval is consumed right before the post (a crash afterwards cannot leave a
reusable approval); afterwards: register entry. A draft whose ID is already in the
register is never submitted again: the dry run reports "ALREADY SUBMITTED" (exit 0),
--submit refuses (exit 1).

Draft (Markdown):

    ```json disclosure
    {
      "id": "omc-06", "channel": "issue", "repo": "owner/name",
      "title": "English issue title",
      "finding": "short title", "severity_class": "non-critical",
      "severity_reason": "...", "upstream_ref": "main@<sha>, v1.2.3",
      "leak_allow": ["Claude Code"]
    }
    ```
    <!-- TEXT -->
    **Summary** ...

For a comment: "channel": "comment", "issue": <number>, no "title".

Reaction in the OWN repository (draft from disclosure_watch.py under
private/disclosures/inbox/reactions/): "channel": "reaction", "repo" (must be listed in
watch_config "own_repos"), "issue", "labels" [..], "close"
null|"completed"|"not_planned"; text = reply comment (may be empty). Approval
with action=reaction; no register entry, log private/disclosures/reactions.jsonl.

Mandatory for issue and comment: field "policy" (check against the upstream
SECURITY.md, see _submit.py). If it is missing, a required content item is false, the
result is not "report", or the SECURITY.md changed since the check (blob SHA per
GET), even the dry run aborts with exit 1.

Other code hosts: field "forge": "<alias>" (from the .env, see forge.py) - GitHub Enterprise,
Gitea/Forgejo or GitLab; writing needs forge_<alias>_write=on. On GitLab a critical finding may
go out as a CONFIDENTIAL issue ("confidential": true): the draft must lie under private/, the
entry stays in the confidential register until 'register.py publish'. Gitea has no
confidential issues (refused).

Critical findings go out as a public issue only if the draft carries
"critical_public": "<reason>" (SECURITY.md asks for issues or there is no
confidential channel - result of channel.py). In addition the leak scan is stricter for
them: its "exploit detail?" findings (PoC, payload, reverse shell, exploit) are ERRORS,
not warnings - a public critical report carries no exploit details.

    python tools/disclosures/issue_submit.py <draft.md>              # dry run
    python tools/disclosures/issue_submit.py <draft.md> --submit     # with approval

Exit 0 ok, 1 leak finding/no approval/policy blocks/already submitted (--submit),
2 operator error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _submit import (already_submitted_exit, approval_note, approval_or_abort, leak_check,  # noqa: E402
                     policy_or_abort, prepare, register_entry, sending, show)
from _common import (REACTIONS_LOG, AlreadySubmitted, DisclosureError, PolicyError,  # noqa: E402
                     err, load_watch_config, now_iso, out, read_draft, sha256_bytes)
from forge import forge_of, target_of  # noqa: E402


def reaction(draft: Path, submit: bool) -> int:
    """Reaction in the OWN repository: comment and/or labels and/or closing.
    Draft from disclosure_watch.py under private/disclosures/inbox/reactions/."""
    meta, text, raw = read_draft(draft)
    if meta.get("channel") != "reaction":
        raise DisclosureError("not a reaction draft")
    f = forge_of(meta)
    repo = f.check_repo(meta.get("repo", ""))
    if target_of(meta) not in (load_watch_config().get("own_repos") or []):
        raise DisclosureError(f"{repo} is not listed in watch_config 'own_repos' - reactions only in the own repository")
    nr = meta.get("issue")
    if not str(nr).isdigit():
        raise DisclosureError("reaction draft without a numeric 'issue'")
    labels = [str(x) for x in meta.get("labels") or []]
    close = meta.get("close")
    if close not in (None, "completed", "not_planned"):
        raise DisclosureError("close: null, 'completed' or 'not_planned'")
    if not text.strip() and not labels and not close:
        raise DisclosureError("reaction without content")
    show({"Channel": "reaction (own repository)", "Repo": target_of(meta), "Issue": f"#{nr}",
          "Labels": ", ".join(labels) or "-", "Close": close or "no"}, text, raw)
    if (text.strip() or labels) and not leak_check(meta, text, *labels):
        out("ERROR: leak scan - do not submit")
        return 1
    if not submit:
        approval_note(meta, raw, "reaction")
        out("DRY RUN: nothing sent. Submit only with approval (action=reaction) + --submit.")
        return 0
    approval_or_abort(meta, raw, "reaction")
    account = f.whoami()
    done = []
    with sending(meta["id"]):           # approval consumed before the first post
        if text.strip():
            k = f.post(f"repos/{repo}/issues/{nr}/comments", {"body": text})
            done.append(f"comment {k.get('html_url')}")
        if labels:
            f.post(f"repos/{repo}/issues/{nr}/labels", {"labels": labels})
            done.append("labels " + ",".join(labels))
        if close:
            f.post(f"repos/{repo}/issues/{nr}", {"state": "closed", "state_reason": close}, method="PATCH")
            done.append(f"closed ({close})")
    REACTIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(REACTIONS_LOG, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"time": now_iso(), "account": account, "repo": target_of(meta), "issue": nr,
                             "done": done, "draft_sha256": sha256_bytes(raw)}) + "\n")
    out("OK: " + "; ".join(done))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Issue/comment/reaction from a draft (default: dry run)")
    ap.add_argument("draft")
    ap.add_argument("--submit", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="default; only for clarity")
    a = ap.parse_args(argv)
    if a.submit and a.dry_run:
        ap.error("--submit and --dry-run are mutually exclusive")
    draft = Path(a.draft)
    try:
        if read_draft(draft)[0].get("channel") == "reaction":
            return reaction(draft, a.submit)
        meta, text, raw = prepare(draft, ("issue", "comment"), ("repo",))
        channel = meta["channel"]
        if channel == "issue" and not meta.get("title"):
            raise DisclosureError("issue draft without 'title'")
        if channel == "comment" and not str(meta.get("issue", "")).isdigit():
            raise DisclosureError("comment draft without a numeric 'issue' - a comment that has to be "
                                  "posted by hand (e.g. on a security advisory: no REST API) is registered "
                                  "afterwards with 'register.py posted <draft> --url <link>'")
        f = forge_of(meta)
        confidential = bool(meta.get("confidential"))
        if confidential and (channel != "issue" or "confidential_issue" not in f.features):
            raise DisclosureError(f"'confidential': true only for a new issue on a forge with confidential "
                                  f"issues (GitLab) - {f.alias} is {f.kind}")
        if "issues" not in f.features:
            raise DisclosureError(f"forge {f.alias} ({f.kind}) has no issue tracker - use mail_report.py")
        if meta["severity_class"] == "critical" and not confidential and not meta.get("critical_public"):
            raise DisclosureError("critical finding as a public issue: only with field "
                                  "'critical_public' (reason from channel.py) - "
                                  "otherwise a confidential channel (advisory_submit.py, mail_report.py, "
                                  "GitLab: \"confidential\": true)")
        head = {"Channel": channel + (" (CONFIDENTIAL)" if confidential else ""), "Repo": target_of(meta)}
        if channel == "issue":
            head["Title"] = meta["title"]
        else:
            head["Issue"] = f"#{meta['issue']}"
        show(head, text, raw)
        clean = leak_check(meta, meta.get("title", ""), text,
                           block_exploit=meta["severity_class"] == "critical" and not confidential)
        if not clean:
            out("ERROR: leak scan - do not submit")
            return 1
        policy_or_abort(meta, text)
        if not a.submit:
            approval_note(meta, raw, channel)
            out("DRY RUN: nothing sent. Submit only with approval + --submit.")
            return 0
        approval_or_abort(meta, raw, channel)
        if not f.write:
            raise DisclosureError(f"forge {f.alias}: writing is off (forge_{f.alias}_write=on in .env)")
        account = f.whoami()
        if channel == "comment":
            f.get(f"repos/{meta['repo']}/issues/{meta['issue']}")    # does it exist? (before consuming)
        with sending(meta["id"]):       # approval consumed before the post
            if channel == "issue":
                payload = {"title": meta["title"], "body": text}
                if confidential:
                    payload["confidential"] = True
                answer = f.post(f"repos/{meta['repo']}/issues", payload)
                reference, url = answer.get("number"), answer.get("html_url")
            else:
                answer = f.post(f"repos/{meta['repo']}/issues/{meta['issue']}/comments", {"body": text})
                reference, url = f"{meta['issue']}#{answer.get('id')}", answer.get("html_url")
        entry = register_entry(meta, draft, channel, reference, url,
                               answer.get("created_at"), account,
                               meta.get("note", ""))
        out(f"OK: {channel} created: {url} - register {entry['id']}")
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
