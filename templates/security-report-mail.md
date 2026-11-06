# Security report by email - draft {{ID}}

Internal part (does NOT go out). Generated with
`python tools/disclosures/mail_report.py new --id {{ID}} --repo {{REPO}} --to {{TO}} --out <file>`.
Fill in all `{{...}}` - sending refuses drafts with placeholders.

- Severity class and reason: in the JSON block.
- Channel (output of `channel.py`): SECURITY.md names the address above.
- Reproduction ONLY briefly; details only on the maintainer's request.
- Before sending: `python tools/disclosures/approval.py show <file>`, present the text to
  the client, after their approval `approval.py grant <file> --action email`,
  then `mail_report.py send <file> --send`.

## Policy check

Basis: `python tools/disclosures/channel.py --policy {{REPO}}` (evidence under
`private/records/<name>/disclosures/policy/`). Assessment per item, result into the field `policy`.
If it is missing, a required content item is `false`, `result` is not `report`, or the
SECURITY.md changed since (blob SHA), approval and sending are refused.

1. Supported versions - is the checked state covered? {{ASSESSMENT_VERSIONS}}
2. Channel and prohibitions (public issue forbidden? address, subject, language, encryption?) - does the policy ask for exactly this mail? {{ASSESSMENT_CHANNEL}}
3. Required content - each item separately in the field `required_content`, does the text meet it? {{ASSESSMENT_REQUIRED_CONTENT}}
4. Scope - in scope / excluded / known limitation / "by design"? Does the finding contradict a promise of the security model? Then quote it verbatim. {{ASSESSMENT_SCOPE}}
5. Testing and disclosure rules (no tests against production systems, deadlines, coordinated publication, bounty, safe harbor) - does the "Disclosure" paragraph fit? {{ASSESSMENT_DISCLOSURE}}
6. Promised response times - number into `response_days` or `response_workdays` (otherwise null). {{ASSESSMENT_DEADLINES}}

Fields in the JSON block below beyond the policy check (JSON takes no comments, so they are explained here):
`"forge"` - code host of the reported repository: `"github"` = github.com, otherwise the alias from the `.env`;
`"exposure"` - `network` or `local`: reachable from outside the machine? Input of the exposure pass, the verdict
must match; critical + `SAFE` additionally needs `"exposure_override": "<reason>"`. Remove the field if you do not
want to state it.

```json disclosure
{
  "id": "{{ID}}",
  "channel": "email",
  "forge": "github",
  "repo": "{{REPO}}",
  "exposure": "{{network|local}}",
  "to": "{{TO}}",
  "subject": "Security report: {{PRODUCT}} - {{SHORT_TITLE}}",
  "finding": "{{FINDING}}",
  "severity_class": "critical",
  "severity_reason": "{{SEVERITY_REASON}}",
  "upstream_ref": "{{BRANCH_AT_SHA_AND_RELEASE}}",
  "policy": {
    "blob_sha": "{{BLOB_SHA_OF_SECURITY_MD_OR_null}}",
    "path": "SECURITY.md",
    "checked_at": "{{DATE}}",
    "versions": "{{VERSIONS}}",
    "channel": "{{CHANNEL}}",
    "required_content": {"{{REQUIRED_CONTENT}}": false},
    "scope": "{{SCOPE}}",
    "deadlines": "{{DEADLINES}}",
    "response_days": null,
    "result": "{{report|reclassify|do-not-report}}"
  },
  "leak_allow": []
}
```

<!-- TEXT -->
Hello,

I would like to report a security issue in {{PRODUCT}} ({{REPO}}) privately, following your
security policy.

Summary
{{SUMMARY}}

Affected versions
{{AFFECTED_VERSIONS}} (checked against {{BRANCH_AT_SHA_AND_RELEASE}}).

Impact
{{IMPACT}}

Where
{{WHERE_PERMALINK}}

Reproduction
{{REPRO_SHORT}}
I can provide a more detailed reproduction on request.

Suggested fix
{{SUGGESTED_FIX}}

Disclosure
I have not published this. I would suggest a coordinated disclosure window of 90 days from
today, or earlier once a fix is released, and I am happy to adjust to your schedule. Please
let me know if you would like me to credit someone else or stay anonymous in any advisory.

Found during an internal security review.

Contact: {{SENDER}}

Best regards,
<sender name>
