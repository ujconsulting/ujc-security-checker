# Implementation <name> — fork `<owner>/<name>-ujc`

<!--
Location: private/repos/<name>/implementation/CHANGELOG.md (private, gitignored; never in the public summary). One entry per fork commit, newest on top.
Sources: `git -C <fork> log --format='%h %ad %s' --date=short <upstream-tag>..HEAD`,
fork `UJC-PATCHES.md` (section per round) and the review round that triggered the commit.
Only what the commit really contains; evidence stated honestly (static / container / unverified).
The local fork path does not go here (public file); it belongs in
private/disclosures/watch_config.local.json -> repos.<owner/repo>.fork_path.
Patches for findings under embargo: neutral wording of what the code change does, no reference
to a finding, a disclosure or an embargo until the disclosure is published.
-->

| | |
|---|---|
| Upstream | `<owner>/<repo>`, base tag `<tag>` = `<sha>` |
| Fork | `<owner>/<name>-ujc` (private) |
| Version scheme | `<upstream>+ujc.<n>` (PEP 440) or `<upstream>-ujc.<n>` (semver, pre-release!) |
| Current state | `<version>` = `<sha>` |

## `<version>` — <DD.MM.YYYY> — `<sha>`

**Commit:** "<commit title>"
**Trigger:** round NN (`reviews/round-NN-<kind>.md`), verdict `<…>`, findings <numbers>.

**What (patch identifiers):**

- `<ID1>` — <one line: what is different now>
- `<ID2>` — …

**Why:** <one to three sentences; class instead of location, decision of the owner>.

**Evidence:** <static: ast.parse / node --check / character scan / generator check; tests:
run in the container on … / not run>.

**Open afterwards:** <what is deliberately not solved, reference to UJC-PATCHES "Open">.
