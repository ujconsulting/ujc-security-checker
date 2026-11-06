[English](README.md) | [Deutsch](README_de.md)

# tools/disclosures - report findings, track disclosures and the inbox

Plain command-line tools: Python 3.10+ (standard library only) plus the `gh` CLI, run from the
checker root. Process, rules, severity classes, embargo: skill
[`finding-disclosure`](../../.claude/skills/finding-disclosure/SKILL.md).

| Tool | writes to the outside? | Purpose |
|---|---|---|
| `forge.py list` / `check <alias> [--repo o/n]` | no (GET) | code hosts besides github.com: configured forges (no secrets) and reachability + login check; module for all tools below (see "Other code hosts") |
| `channel.py <o/r> [--file P --lines a-b] [--duplicates "..."] [--out F]` | no (GET) | default branch + SHA, release, SECURITY.md, PVR, channel recommendation, file at the current state, duplicates (`--policy` fetches the policy files by the recorded commit SHA) |
| `channel.py --policy <o/r> [--store <folder>] [--out <file>]` | no (GET); stores locally | SECURITY.md (`.github/`, root, `docs/` - GitHub's order of precedence - otherwise `<owner>/.github`) + referenced policies + CONTRIBUTING with a security section as evidence `private/records/<record>/disclosures/policy/SECURITY-<blob7>.md` (+ `.evidence.json` with blob SHA, SHA-256, commit); checklist (versions, channel, required content, model/scope, deadlines, testing/disclosure) and a skeleton for the draft field `policy` |
| `leak_scan.py <draft>` / `--text <file>` | no | AI hints, local paths, internal addresses, credentials, internal names (shared deny list `private/public_check_denylist.txt`, optional extra `private/disclosures/leak_names.txt`) |
| `codex_check.py run\|finding\|exposure <draft> --source quarantine/<name>` / `status` / `config` | no (Codex read-only via `tools/codex_ro.py`) | Codex cross-check of the outgoing text against the upstream source at the referenced commit - every claim CONFIRMED / WRONG / OVERSTATED / NOT VERIFIABLE, last line `CHECK: CONFIRMED` or `CHECK: CORRECTIONS NEEDED`; record `private/repos/<record>/disclosures/checks/<id>.check` bound to the draft hash. Only active with `disclosure_codex_check=on\|critical` in `.env`. `finding` validates the finding itself (`FINDING: CONFIRMED` / `NOT CONFIRMED` / `SEVERITY WRONG`), `exposure` the reachability from outside (`EXPOSURE: UNSAFE` / `SAFE`) - see "Codex gates"; `config` prints the effective switches, models and efforts |
| `approval.py show/grant/status/revoke` | no (GET for the policy check) | hash-bound one-time approval `private/repos/<record>/disclosures/approvals/<id>.approval`; refused without a valid policy check, without the confirmed Codex gates (text check, finding validation, exposure pass - each if switched on) or if the ID is already in the register |
| `issue_submit.py <draft> [--submit]` | **yes**, only with approval | public issue, comment, reaction in the own repository (comment/labels/closing); on GitLab also a confidential issue (`"confidential": true`) |
| `advisory_submit.py <draft> [--submit]` | **yes**, only with approval | private vulnerability reporting (GitHub-type forges only) |
| `mail_report.py new/send/inbox/config`, `--check-connection` | **yes** (`send --send`), only with approval | mail via the own security mailbox (address from `.env`: `security_mail_address`, sender name `security_mail_sender_name`, default "Security Team"; never in the repository; sending with the placeholder is refused); mailbox read-only. `send --send` writes a marker `private/disclosures/sending/<id>.json` before the SMTP send and removes it after the register entry; while it exists a new send is refused (the mail may have gone out - check the Sent folder, reconcile by hand). `inbox` reads at most 200 messages per run and stores the highest UID actually processed (the rest is reported as pending); a message matched to an entry by subject/Message-ID is an unverified lead |
| `register.py check/readme/new/publish/migrate/posted` | no (publish: GET) | registers per record (public + confidential), overviews `REGISTER.md` + `REGISTER_de.md`, lift the embargo; `migrate --record <name> [--dry-run]` moves legacy root entries into the record; `posted <draft> --url <link> [--reference R] [--created ISO] [--account A]` records a disclosure posted **by hand** (e.g. a comment on a security advisory - no REST API) under the same gates as a submit tool (fields, leak scan, policy, Codex gates, hash-bound approval for the draft's channel); https link into the repository, reference from the link (draft field `"advisory": "<GHSA>#<fragment>"`), a draft under `private/` makes the entry confidential; `new` takes `--id`, `--confidential`, `--record` |
| `disclosure_watch.py [--flag] [--since D] [--no-mail] [--no-repos] [--no-save]` | no (GET, EXAMINE) | watch: disclosures, own repository, mailbox, upstream repositories with value classification (also on other code hosts: forge entries; GitLab lists issues only; own logins `forge_<alias>_accounts`). Leads that rest on third-party text (a #number named in a comment, a mail matched by subject/Message-ID) are reported as unverified and never advance the status. Nothing from a private own repository and no item with security wording in its text or comments goes into the public report. An unreadable own repository and a reached item cap are reported (unreadable: exit 2; cap: the marker stays at the last processed item) |
| `own_repo.py` | - | module: classification and reaction drafts for the own repository |
| `own_repos_check.py [--accounts A ...] [--out F]` | no (GET); writes the overview file `--out` (default `disclosures/own_repos.md`) | own public repositories: PVR, SECURITY.md, address (accounts as `<alias>:<account>` for other forges; where a forge has no PVR the SECURITY.md must name a channel) |
| `scheduled_task_setup.ps1 [-Install] [-Remove] [-Time HH:MM] [-DayOfWeek <day>]` | local (Task Scheduler) | daily watch, or weekly with `-DayOfWeek` - **only after approval** |

Storage (rule since 12.10.2026): `disclosures/` and `private/disclosures/` in the root hold only what
belongs to the checker itself (inbox of its own repository, `own_repos.md`, `watch_config*`, its own
findings, `seen.json`, `mail_status.json`, `NEW.flag`, `reactions.jsonl`, `leak_names.txt`).
Everything about a reviewed repository lives with its record, and nothing of it is versioned
(only the summary `repos/<record>/README.md` + `README_de.md` is; since 06.11.2026): the formerly
public part in `private/records/<record>/disclosures/` (`register.json`, generated `REGISTER.md` +
`REGISTER_de.md`, `reports/`, drafts of non-critical findings, `policy/`), the checker's own
non-confidential reports in `private/disclosures/public-reports/`, confidential in `private/repos/<record>/disclosures/` (`register.json`, `REGISTER.md`,
`approvals/`, `checks/`, `reports/`, `reply-drafts/`, critical drafts). The record of an entry is
the field `record`, else the draft's folder, else the record whose README names the repository as
"Upstream"; a disclosure to a foreign repository without a record is refused before anything goes
out (`_submit.record_or_abort`), own repositories (`own_repos` in the watch config) stay in the
root. `disclosure_watch.py` writes its reports and reply drafts per record the same way. All
locations are derived at run time from the current register location, so a self-test never
touches the real overviews.

Draft format: Markdown with an internal head, a ```` ```json disclosure ```` block and the marker
`<!-- TEXT -->`; everything after the marker goes out byte for byte. Templates:
`templates/advisory-draft.md`, `templates/issue-draft.md`, `templates/security-report-mail.md`.
The marker must occur exactly once and after the JSON block, otherwise the draft is refused.

Fail-closed rules of the submit tools: the policy check always uses the disclosure's own `repo`
(`policy.repo` may only name `<owner>/.github`); an HTTP 403 from GitHub is an error, never
"not found" (only 404 means "no SECURITY.md"); a critical finding as a public issue/comment
treats the leak scan's "exploit detail?" findings (PoC, payload, reverse shell, exploit) as
errors; the leak scan covers every field that is sent (advisory: summary, description and the
serialised `vulnerabilities`, cvss, cwe_ids; reaction: labels); `register.py publish` only marks
the entry as public and leaves the draft where it is; register writes are atomic and serialised by a lock
file `private/disclosures/register.lock` (stale after 10 minutes).

Policy check (mandatory for issue, comment, advisory, email): every draft carries the field
`policy` in its JSON block (format: `_submit.py`, templates under `templates/`).
`approval.py grant`, the submit tools and `mail_report.py send` abort - already in the dry run -
with exit 1 if it is missing, a required content item is not `true`, `result` is not `report`,
or the current upstream SECURITY.md (GET, blob SHA) differs from the checked state ("policy
changed, check again"). Without a SECURITY.md: `blob_sha: null`, the assessment stays mandatory.
A promised response time (`response_days` / `response_workdays`) goes into the register;
`disclosure_watch.py` reports "deadline passed without response".

Codex cross-check (optional, switched on per project in `.env`: `disclosure_codex_check=on`,
`disclosure_codex_model` default `gpt-6.1-sol`, `disclosure_codex_effort` default `medium`,
template `.env.example`): **not an audit**. Codex gets only the text that goes out (head fields +
text after the marker, never the internal part) and checks each statement in it against a
quarantine clone on a commit named in `upstream_ref`; it does not look for new findings. When
switched on, `approval.py grant` and every submit tool refuse with exit 1 unless a record for
exactly the current draft hash exists, ran with the configured model/effort, and the unchanged
Codex output ends with `CHECK: CONFIRMED`. A corrected draft has a new hash and needs a new
cross-check and a new approval. Reactions in the own repository are not reports and need none.

Codex gates (claudex integration): besides the text check two further gates check the finding
itself, each with its own switch (`off` | `critical` | `all`), model and effort. Without a model
in `.env` the role configuration of claudex-loop is asked (`claudex_loop_dir` ->
`claudex_roles.py --spec <role>`), otherwise the default `gpt-6.1-sol` / `medium` applies.

| Gate | Switch / model / effort | Question | Passes with |
|---|---|---|---|
| text check (`run`) | `disclosure_codex_check=on\|critical\|off`, `disclosure_codex_channels`, `disclosure_codex_timeout` | is every claim in the outgoing text correct? | `CHECK: CONFIRMED` |
| finding validation (`finding`) | `claudex_finding_check`, `claudex_finding_model`, `claudex_finding_effort` (role `code-review`) | is the finding real at the referenced commit, are preconditions, severity class and rating supported, is it by design per the policy? | `FINDING: CONFIRMED` (`NOT CONFIRMED` and `SEVERITY WRONG` block) |
| exposure pass (`exposure`) | `claudex_exposure_check`, `claudex_exposure_model`, `claudex_exposure_effort` (role `exposure-review`) | is the affected code reachable from outside the machine, and by whom? | a verdict consistent with the draft field `exposure` (`network` = `EXPOSURE: UNSAFE`, `local` = `SAFE`); a critical finding with `SAFE` needs `"exposure_override": "<reason>"` |

The finding and exposure records (`private/repos/<record>/disclosures/checks/<id>.finding.check`,
`<id>.exposure.check`) are bound to a digest of the finding fields (finding, severity, rating,
`upstream_ref`, exposure, repo, forge), not to the wording: correcting the text needs a new text
check only. `approval.py grant` and every submit tool test all three gates (`_submit.py
codex_check_or_abort`); one Codex run at a time, never in parallel. Exit 4 = Codex usage limit
(nothing recorded, run again later), exit 3 = Codex could not execute commands (the check did not
happen). `--source` is a clone under `quarantine/` on a commit named in `upstream_ref`
(`tools/quarantine_clone.py`, also for Gitea, GitLab and other git servers).

Other code hosts (`forge.py`): besides github.com the tools address GitHub Enterprise / own
GitHub servers, Gitea (Forgejo), GitLab (gitlab.com or self-managed, subgroups) and plain git
servers without an API as `<alias>:owner/name` (GitLab also `<alias>:group/sub/name`). The alias
comes from a block `forge_<alias>_*` in `.env` (template `.env.example`: `type`, `url`, `token`,
`ca_bundle`, `tls_verify`, `allow_http`, `write`, `accounts`, `timeout`). The tools keep speaking
GitHub-style paths; `forge.py` translates them for Gitea and GitLab. Features a forge lacks
(PVR, advisories, alerts) answer "not available". `write=off` is the default: submit tools write
only to a forge with `forge_<alias>_write=on`, through the same hash-bound approval; the token goes
only to the configured API host. Type `git` never writes and never runs repository code.

```bash
python tools/disclosures/forge.py list               # configured forges, no secrets
python tools/disclosures/forge.py check <alias>      # reachability + login, GET only
python tools/disclosures/channel.py lan:tools/scanner --duplicates "path traversal"
```

Optional draft fields (JSON block): `forge` (alias; absent = github.com), `confidential`
(`true` = GitLab confidential issue for a critical finding; the draft must lie under `private/`
and stays in the confidential register until `register.py publish`; Gitea has no confidential
issues and refuses), `exposure` (`"network"` | `"local"`, input of the exposure pass),
`exposure_override` (reason, see above).

No double submission: a draft whose `id` is already in the register (public or confidential
part) is never submitted again. The dry run prints `ALREADY SUBMITTED: ...` and exits 0,
`--submit` / `--send` refuse with exit 1, `approval.py grant` refuses with exit 1.

The dry run is the default everywhere. Writing GitHub calls exist only in
`_common.gh_post` (POST, PATCH for closing own issues), SMTP and IMAP APPEND only in
`mail_report.py send`; all of them run only after `check_approval()` with a matching SHA-256
and consume the approval - BEFORE the external call (a crash after posting cannot leave a
reusable approval; if the call fails, a new grant is needed - check the target first). The Codex
check record stays as evidence. The mailbox is only opened read-only (EXAMINE, BODY.PEEK).

Approval file format (`private/repos/<record>/disclosures/approvals/<id>.approval`):

```text
action=<issue|comment|advisory|email|reaction>
sha256=<SHA-256 of the draft file>
granted=<ISO time>
note=<who approved when>
```

Environment variables: `UJC_VAULT_ENV` (location of `vault_env.py`, mailbox only),
`security_mail_*` (override the `.env`), `UJC_CHECKER_ROOT` (another root, for tests).

Self-tests (no network):

```bash
python tools/disclosures/leak_scan.py --self-test
python tools/disclosures/advisory_submit.py --self-test
python tools/disclosures/mail_report.py --self-test
python tools/disclosures/disclosure_watch.py --self-test
python tools/disclosures/approval.py --self-test      # policy check, approval, dry run, double submission
python tools/disclosures/codex_check.py --self-test   # switches, hash binding, three gates in approval and submit
python tools/disclosures/forge.py --self-test         # address parsing, path translation, safety rules
python tools/disclosures/channel.py --self-test       # policy heuristic, blob SHA
```

Exit codes: 0 ok / nothing new, 1 finding (leak, news, gap, no approval, already submitted
with `--submit`), 2 operator error (gh not logged in, file missing, connection failed).
Console output is ASCII.
