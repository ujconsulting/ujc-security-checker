[English](README.md) | [Deutsch](README_de.md)

# linkedin-skills - review summary

| | |
|---|---|
| What | Bundle of 12 agent skills for LinkedIn content (writing, commenting, replying, planning, analytics) plus a small Python helper that reads through scraping actors and publishes through a third-party API |
| Type | Agent skill bundle / plugin with a Python helper library; no hooks, no server, no package-manager install |
| Upstream | `sergebulaev/linkedin-skills` - license MIT |
| Reviewed version | tag `v1.1.28` = `8f8bc4b40a2d5419b2dcf898772b85712cfbdf41` |
| Reviewed on | 31.10.2026 |
| Verdict | `USABLE WITH CONDITIONS` (Claude audit only; Codex audit not yet run) |
| Recommendation | use only with conditions |

## Assessment

The skills are mostly instructions for the agent, and by default they only produce drafts that the user
posts by hand. The code matters only once publishing or reading keys are configured. In that mode the
approval step before publishing is written as prose, not enforced in code, so a misled or careless agent
could publish immediately. Defences against untrusted content are partly prose with gaps, and stored
profile data could keep injected text. No telemetry, auto-update, hooks or settings changes were found,
and the network targets are fixed. There are also platform-terms and data-protection concerns around
scraping and automated posting. Overall the risk is low in draft mode and moderate with keys enabled.

## Main risks

- Human approval before publishing is not enforced by the code once keys are set.
- Prompt-injection defences for third-party content are incomplete, and stored profile data can persist injected text.
- Configuration files are searched in parent directories, and personal data is written into the plugin folder.
- Scraping and volume or automation advice conflicts with the platform terms and raises data-protection questions.
- Publishing calls can be retried without safeguards against duplicates.
- Unpinned install routes, an optional external command backend, and a commercial referral funnel.

## Recommendation

Fine for drafting use: install a fixed copy of the reviewed version in project scope, run without any
keys, and use only the drafting skills. If publishing is enabled, use a single publishing key stored
locally, keep script execution on per-call approval, never on an allowlist, leave the scheduling and custom
posting paths unused (approval written only in the skill text does not restrain the publishing code), avoid scraping-based features and unattended sessions,
keep personal data out of version control, and verify every figure in a draft yourself.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
