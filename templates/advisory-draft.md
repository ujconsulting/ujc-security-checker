# Advisory draft (private vulnerability reporting) <NN> - <short title>

Internal part (does NOT go out).

- Channel: `channel.py <o/r>` -> PVR on, SECURITY.md asks for no other channel.
- Fields per the GitHub REST OpenAPI (`POST repos/{owner}/{repo}/security-advisories/reports`):
  `summary` (<=1024), description = text after the marker (<=65535), EXACTLY ONE of
  `severity` (critical|high|medium|low) or `cvss_vector_string`, `cwe_ids`,
  `vulnerabilities[]` with `package.ecosystem` (rubygems, npm, pip, maven, nuget, composer, go,
  rust, erlang, actions, pub, other, swift), `package.name`, `vulnerable_version_range`,
  optional `patched_versions`, `vulnerable_functions`; optional `start_private_fork`.
- Flow: `advisory_submit.py <file>` (dry run) -> present the text -> `approval.py grant
  <file> --action advisory --note "..."` -> `advisory_submit.py <file> --submit`.

## Policy check

Basis: `channel.py --policy <o/r>` (evidence `private/records/<name>/disclosures/policy/SECURITY-<blob7>.md`).
Result into the field `policy`; if it is missing, a required content item is `false`, `result` is
not `report`, or the current SECURITY.md differs (blob SHA), there is neither approval nor submission.

1. Supported versions: <quote> - checked state <tag> -> <met/not met>.
2. Channel and prohibitions: <quote> -> <PVR/mail; label, language>.
3. Required content: <per item: section in the text>.
4. Scope: <in scope / excluded / known limitation / by design>; promise of the security model that the finding contradicts: "<verbatim quote>".
5. Testing and disclosure rules: <deadlines, coordinated publication, bounty, safe harbor, testing prohibitions> -> does the "Disclosure" paragraph fit?
6. Response times: <quote> -> `response_days` <number or null>.

Fields in the JSON block below beyond the policy check (JSON takes no comments, so they are explained here):
`"forge"` - `"github"` = github.com, otherwise the alias of a GitHub-type forge from the `.env` (PVR exists only there);
`"exposure"` - `"network"` or `"local"`: reachable from outside the machine? Input of the exposure pass, the
verdict must match; critical + `SAFE` additionally needs `"exposure_override": "<reason>"`. Remove the field if
you do not want to state it.

```json disclosure
{
  "id": "<repo-short>-NN",
  "channel": "advisory",
  "forge": "github",
  "repo": "<owner>/<name>",
  "exposure": "<network|local>",
  "summary": "<English one-line summary>",
  "severity": "high",
  "cwe_ids": ["CWE-<n>"],
  "vulnerabilities": [
    {"package": {"ecosystem": "pip", "name": "<package>"}, "vulnerable_version_range": "<= <version>"}
  ],
  "finding": "<short title>",
  "severity_class": "critical",
  "severity_reason": "<one sentence: class + realistic trigger>",
  "upstream_ref": "<branch>@<sha>, <tag>",
  "policy": {
    "blob_sha": "<blob SHA from channel.py --policy, or null without SECURITY.md>",
    "path": "SECURITY.md",
    "checked_at": "<YYYY-MM-DD>",
    "versions": "<supported per policy; checked; met?>",
    "channel": "<requested channel, prohibitions>",
    "required_content": {"<required content per policy>": false},
    "scope": "<in scope / excluded / by design; promise>",
    "deadlines": "<response/disclosure deadlines per policy>",
    "response_days": null,
    "result": "<report|reclassify|do-not-report>"
  },
  "leak_allow": []
}
```

<!-- TEXT -->
### Summary

<One or two sentences: what goes wrong and what an attacker gains.>

### Details

<What the code does; affected versions as a sentence.>

- `<path/to/file>` L<a>-L<b>: <what the code does>
- Permalink: https://github.com/<owner>/<name>/blob/<sha>/<path>#L<a>-L<b>

### Potential impact

<We rate this <severity> (CVSS <score>); who is affected, under which realistic conditions, what an attacker gains.>

### Steps to reproduce

<Short outline; a full proof of concept is available on request.>

### Suggested fix

1. <...>

### Disclosure

Not published elsewhere. Happy to coordinate timing; 90 days or the fix release, whichever is earlier, unless you prefer otherwise.

Found during an internal security review.
