# Issue draft <NN> - <short title>

Internal part (does NOT go out): state of the check, duplicates, recommendation.

- Status: checked against `<branch>@<sha>` and release `<tag>` - still applies (file L a-b).
- Duplicates: `channel.py <o/r> --duplicates "<terms>"` - result.
- Severity class: see JSON; critical only with `critical_public` (SECURITY.md asks for issues
  or there is no confidential channel) and then WITHOUT exploit details.
- Flow: `issue_submit.py <file>` (dry run) -> present the text -> `approval.py grant
  <file> --action issue --note "..."` -> `issue_submit.py <file> --submit`.

## Policy check

Mandatory for public issues too: does the SECURITY.md allow this finding in public?
Basis `channel.py --policy <o/r>`. Result into the field `policy` (otherwise no
approval, no submission). `required_content` may stay empty for a non-critical issue
if the policy asks for content only for security reports - then say so here.

1. Supported versions: <quote> -> <met/not met>.
2. Channel and prohibitions: does the policy forbid public issues for vulnerabilities? Is this finding a vulnerability under its model? Label, language?
3. Required content: <applies / does not apply to this issue, reason>.
4. Scope: <in scope / excluded / known limitation / by design>; the relevant passage of the model verbatim.
5. Testing and disclosure rules: <affected? no>.
6. Response times: <quote> -> `response_days` <number or null>.

Fields in the JSON block below beyond the policy check (JSON takes no comments, so they are explained here):
`"forge"` - code host: `"github"` = github.com, otherwise the alias from the `.env` (`forge_<alias>_*`);
`"confidential"` - `true` only on GitLab: critical finding as a confidential issue (draft under `private/`);
`"exposure"` - `"network"` or `"local"`: reachable from outside the machine? Input of the exposure pass, the
verdict must match; critical + `SAFE` additionally needs `"exposure_override": "<reason>"`. Remove the field if
you do not want to state it (the exposure pass then only records its verdict).

```json disclosure
{
  "id": "<repo-short>-NN",
  "channel": "issue",
  "forge": "github",
  "repo": "<owner>/<name>",
  "confidential": false,
  "exposure": "<network|local>",
  "title": "<English title: component - what goes wrong>",
  "finding": "<short title>",
  "severity_class": "non-critical",
  "severity_reason": "<one sentence>",
  "upstream_ref": "<branch>@<sha>, <tag>",
  "policy": {
    "blob_sha": "<security_md.blob_sha of the evidence file from channel.py --policy, or null without SECURITY.md>",
    "path": "SECURITY.md",
    "checked_at": "<YYYY-MM-DD>",
    "versions": "<supported per policy; met?>",
    "channel": "<public issue allowed because ...>",
    "required_content": {},
    "scope": "<not a vulnerability under the model because ...>",
    "deadlines": "<per policy>",
    "response_days": null,
    "result": "<report|reclassify|do-not-report>"
  },
  "leak_allow": []
}
```

<!-- TEXT -->
**Summary**

<What happens, in two or three sentences.>

**Where**

- `<path/to/file>` L<a>-L<b>: <what the code does>
- Permalink: https://github.com/<owner>/<name>/blob/<sha>/<path>#L<a>-L<b>
- Same code in <release tag>.

**Why it matters**

<Consequence for users, without step-by-step exploitation.>

**Suggested fix**

1. <...>
2. <...>

**Environment**

<Product> <version> (also checked on current `<branch>`), <OS>. Found during an internal security review.
