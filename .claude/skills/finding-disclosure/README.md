<!-- source: SKILL.md sha256:2e823f418bee07a81aeeb21e43b3ab1ab0383b5f44651b5bbd040d645ceb7652 -->
[English](README.md) | [Deutsch](README_de.md)

# finding-disclosure

Short human documentation. The agents load [`SKILL.md`](SKILL.md), which is authoritative.

## Purpose

Reports findings from a tool review to the upstream project and tracks everything that follows:
answers, linked PRs, advisories, mails, deadlines - plus the inbox of our own public repository and
the security mailbox. Nothing leaves the machine without a hash-bound, one-time approval of
exactly that text. Everything about a reviewed repository (register, approvals, Codex records,
reports, reply drafts) lives with its local record (`private/records/<name>/disclosures/`); the root `disclosures/`
holds only the checker's own.

## When to use

- findings are to be reported upstream;
- someone asks for answers or fixes on our reports;
- our own repository or the mailbox received something;
- an own repository becomes public (private vulnerability reporting first, then `SECURITY.md`).

## Flow

1. **Classify** each finding: critical (confidential channel, draft under `private/`, embargo) or
   non-critical (public issue).
2. **Channel** read-only: `SECURITY.md`, private vulnerability reporting, address. Other code hosts
   (GitHub Enterprise, Gitea/Forgejo, GitLab, plain git) are addressed as `<alias>:owner/name` in
   every step (channel, policy, duplicate search, submission, watch); Gitea and plain git have no
   PVR and no confidential issues (address from `SECURITY.md`, else a public issue without
   details), GitLab has confidential issues.
3. **Policy check** (mandatory): read the upstream security policy completely, store it as
   evidence, assess six items per finding (versions, channel, required content, scope/"by
   design", disclosure rules, response times).
4. **Current state and duplicates** - does the finding still apply on the default branch?
5. **Draft** from a template, without any AI hint, local paths or internal names. If switched on
   in `.env` (critical findings by default), then the **finding validation** (`FINDING: CONFIRMED`
   needed; `NOT CONFIRMED` / `SEVERITY WRONG` = check the code, correct or drop) and the
   **exposure pass** (`EXPOSURE: UNSAFE/SAFE` must match the draft field `exposure`; critical +
   `SAFE` needs `exposure_override`), before the text check and the approval.
6. **Show and leak-scan** the text; if switched on in `.env`, a **Codex cross-check** of every
   claim against the upstream source (not an audit); then **approval** bound to its SHA-256. All
   Codex runs one at a time, never in parallel; exit 4 = quota, wait.
7. **Submit** - always a dry run first, then with the switch; the register of the record is updated.
   A disclosure posted by hand (comment on a security advisory) is recorded with `register.py posted`;
   a foreign repository without a record is refused before anything goes out.
8. **Watch** (read only) and, after publication, **lift the embargo**. The public
   summary never mentions a disclosure - no counter, no dates, no order.

## Commands

```bash
python tools/disclosures/channel.py <owner/repo> --out .claudex-tmp/<name>/channel.md
python tools/disclosures/channel.py --policy <owner/repo> --out .claudex-tmp/<name>/policy.md
python tools/disclosures/approval.py show <draft>
python tools/disclosures/forge.py list | check <alias>      # other code hosts, <alias>:owner/name
python tools/disclosures/codex_check.py config              # effective switches, model/effort
python tools/disclosures/codex_check.py finding  <draft> --source quarantine/<name>   # if switched on
python tools/disclosures/codex_check.py exposure <draft> --source quarantine/<name>   # if switched on
python tools/disclosures/codex_check.py run <draft> --source quarantine/<name>        # text check, if switched on
python tools/disclosures/approval.py grant <draft> --action issue --note "<who, when>"
python tools/disclosures/issue_submit.py <draft>            # dry run
python tools/disclosures/issue_submit.py <draft> --submit
python tools/disclosures/advisory_submit.py <draft> [--submit]
python tools/disclosures/mail_report.py send <draft> [--send]
python tools/disclosures/disclosure_watch.py               # read-only watch
python tools/disclosures/register.py publish <id>          # after publication
python tools/disclosures/register.py set <id> --status answered --severity high --category injection   # stamps answered_at / fixed_at
python tools/disclosures/register.py set <id> --verification verified-fixed   # our check of the fixed code; needed for status fixed
python tools/disclosures/register.py migrate --record <name> [--dry-run]   # legacy root entries
python tools/disclosures/register.py posted <draft> --url <link>          # posted by hand
python tools/disclosures/own_repos_check.py                # own public repositories
```

## Example

A non-critical bug (uninstall removes other tools' hooks): policy checked, no duplicate, draft
`private/records/<name>/disclosures/N1-issue.md`, leak scan clean, the owner reads the text, approval with
`--action issue`, dry run, `--submit`. A day later the watch reports a maintainer comment "fixed in
#123" - a claim; `fixed` is set only after reading the merged files.

## See also

[`tools/disclosures/README.md`](../../../tools/disclosures/README.md),
[`disclosures/README.md`](../../../disclosures/README.md), [`SECURITY.md`](../../../SECURITY.md).
