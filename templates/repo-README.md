[English](README.md) | [Deutsch](README_de.md)

# <name> - review summary

<!--
Location: repos/<name>/README.md (plus the German README_de.md). This is the ONLY versioned file
of a record: a short public summary of the review of the UPSTREAM tool. Remove this comment.
Rules:
- No exploit details, no file paths, no line numbers, no payloads, no reproduction steps.
- Nothing about own use: no usage recommendation for own projects, no customer names, no local paths,
  nothing about an own version (fork, hardened copy, state, patch rounds, changelog, deployment).
- Details (review rounds, scanner output, upstream research, disclosures and their register, reports,
  policy evidence) go to private/records/<name>/ (gitignored): reviews/, disclosures/, record-full.md.
  Own version and usage: private/repos/<name>/.
- The rows "Upstream" and "Recommendation" are read by tools/disclosures/disclosure_watch.py and
  tools/export_dashboard.py: keep the row names. A local fork path belongs in
  private/disclosures/watch_config.local.json -> repos.<owner/repo>.fork_path, not here.
- German version: translate and run `python tools/public_check.py --stamp repos/<name>/README_de.md`.
-->

| | |
|---|---|
| What | <one sentence: what the tool does> |
| Type | Claude Code plugin / skill / MCP server / CLI / Python package / npm package / Docker image |
| Upstream | `<owner>/<repo>` - license `<...>` |
| Reviewed version | tag `<tag>` = `<sha>` |
| Reviewed on | <DD.MM.YYYY> |
| Verdict | `<VERDICT line>` |
| Recommendation | <use / use only with conditions / do not use> |

## Assessment
<Three to six sentences: what the tool does, whether the published package matched the source, the main
concern in general terms, and whether upstream fixed the open points. No technical detail that helps an attacker.>

## Main risks
- <risk in one sentence, general terms>
- <risk in one sentence, general terms>

## Recommendation
<Two to four sentences for readers: under which conditions the tool is acceptable, or why not.>

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
