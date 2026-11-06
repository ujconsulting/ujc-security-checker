<!-- source: SKILL.md sha256:da80398d900bc31cad31b09ac46fef4886043a96ecacda5420d48761c60bd9a9 -->
[English](README.md) | [Deutsch](README_de.md)

# tool-review

Short human documentation. The agents load [`SKILL.md`](SKILL.md), which is authoritative.

## Purpose

The whole process for reviewing an external tool (GitHub repository, Claude Code plugin, skill, MCP
server, CLI, Python or npm package) before it is used, and - if it is worth it but not safe as it
is - adopting it as a private, hardened fork. Every step ends with an abort criterion.

**Public result = summary only; own version -> `private/repos/<name>/`.** The public
`repos/<name>/` holds only a summary (pinned version, verdict, recommendation, assessment); audits,
review rounds, research and disclosure drafts stay local under `private/records/<name>/`; fork,
patch rounds, final tests, changelog and deployment stay private.

## When to use

- a new tool is to be reviewed;
- a patch round or a final test of a fork is due;
- a fork moves to a new upstream release;
- hardening or release of a third-party tool is discussed.

## Flow

1. **Intake** - purpose and intended use; local record `private/records/<name>/`, row in the index of
   the project README (upstream @ version, review date, verdict, recommendation). At the end of the
   review the public summary `repos/<name>/README.md` is written from `templates/repo-README.md`.
2. **Quarantine clone** on a fixed tag under `quarantine/<name>/` from any source (`owner/name`,
   `<alias>:owner/name` on another code host, git URL, local path) with `tools/quarantine_clone.py`; determine what actually runs
   (manifests, hooks, entry points, bundles).
3. **Supply chain** - published package against the tag, bundles against the source.
4. **Scanners** in the scanner image.
5. **Initial audit** - the same audit brief to a Claude sub-agent and to Codex; findings verified
   against the code. With `claudex_audit_mode=audit|both` (default `form`) the Codex half is the claudex-loop
   skill `/audit` on the clone (baseline under `.claudex-tmp/<name>/audit/`, started from the
   checker root; `python tools/disclosures/codex_check.py config` shows model/effort). Optionally a
   CodeRabbit full review (opt-in via `coderabbit_review=on`; public repos go through, non-public needs approval) and further
   second opinions.
6. **Upstream research** - mandatory twice: a general pass before the initial audit (advisories,
   security issues/PRs) and a pass per finding before it is rated (issues and PRs, open and
   closed, every related hit read completely): fixed, intended ("by design"), duplicate or new,
   useful open PRs.
7. **Usage analysis** (skill `usage-analysis`, private).
8. **Decision** of the owner - do not use / use as it is / harden a fork, with a threat model.
9. **Fork and patch rounds** - close classes, disable what is not needed, one commit per round;
   documented only under `private/repos/<name>/`.
10. **Final test** per round, findings of the previous round first (result in `private/repos/<name>/reviews/`).
11. **Container tests** and **behavior probe** - only after approval, only in the egress network
    (result in `private/repos/<name>/reviews/`).
12. **Release**, 13. **maintenance** (both private), 14. **disclosures** (skill `finding-disclosure`).
15. **Ledgers** alongside every step (`tools/ledger.py`, private): decision per record, every
    review run (Codex runs through `ledger.py run codex`), finding metadata without free text.

Never without an instruction from the owner: installing or executing anything from the tool, a
push, a disclosure, a Codex effort above medium, two Codex runs in parallel.

## Commands

```bash
python tools/quarantine_clone.py <source> <name> --ref <tag-or-sha>   # owner/name, alias:owner/name, URL, path
tools/scan.sh quarantine/<name> .claudex-tmp/<name>/scan
python tools/codex_ro.py --model gpt-6-sol --effort medium \
    --prompt-file .claudex-tmp/<name>/codex-prompt.txt \
    --out-file .claudex-tmp/<name>/codex-initial-audit.txt \
    --err-file .claudex-tmp/<name>/codex-initial-audit-err.txt
tools/cr_full_review.sh quarantine/<name> <tag>                 # prepare, shows scope + quota
UJC_CR_YES=1 tools/cr_full_review.sh quarantine/<name> <tag>    # after announcing it
UJC_TEST_APPROVAL=<fork-sha>[+<upstream-sha>] tools/container_test_python.sh <fork> <ref> <upstream-tag> <extras>   # after approval
UJC_PROBE_APPROVAL=<commit-sha> tools/behavior_probe.sh quarantine/<name> <ref> '<entry point>'   # offline by default; UJC_PROBE_ONLINE=1 to keep the network
python tools/ledger.py run codex --record <name> --round <NN> --step final-test --commit <sha> -- <codex_ro.py args>
python tools/ledger.py finding add --record <name> --id r<NN>-<id> --severity high --category injection --status open
python tools/ledger.py check
```

## Example

A Python plugin is to be used in several projects: intake with its purpose, quarantine clone on
`v1.2.3`, wheel downloaded and compared with the tag ("identical"), scanners without hits worth
noting, Claude and Codex both report one finding about an auto-update check. Decision "harden a
fork": the update check is disabled at the entry point, the final test confirms it,
`FINAL TEST: APPROVED`, container tests after approval, release.

## See also

[`docs/SKILLS.md`](../../../docs/SKILLS.md), [`tools/README.md`](../../../tools/README.md),
[`templates/`](../../../templates/), [`AGENTS.md`](../../../AGENTS.md) (Codex reviewer role).
