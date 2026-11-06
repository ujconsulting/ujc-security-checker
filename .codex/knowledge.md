# ujc-security-checker - knowledge digest for Codex CLI

As of 10.10.2026. Operator context (locations, machines): if present,
`private/AGENTS.private.md`.

- Public summaries are under `repos/`, the records under `private/records/`.
- Lesson of October 2026: narrow the threat model early; before that, every final test ran
  against a "hostile repository" and found the next layer each time.
- Built bundles (`dist/`, `bridge/`) are often gitignored in forks but checked in - always search
  with `rg --no-ignore --hidden`.
- The findings of the previous round are re-checked one by one first in every final test.
