[English](README.md) | [Deutsch](README_de.md)

# agents-office - review summary

| | |
|---|---|
| What | Local web application in which many AI agents work on tasks, chats and scheduled routines using the user's connected services |
| Type | Node.js application installed from a git repository (no published package) |
| Upstream | `ajsahni/agents-office` - license PolyForm Noncommercial 1.0.0 plus additional terms |
| Reviewed version | tag `v3.2.1-beta.2` = `f8be2666d062903ff53bb72fad0db31740d020a2` |
| Reviewed on | 12.10.2026 |
| Verdict | `DO NOT USE` (Claude initial audit; no second reviewer) |
| Recommendation | do not use as shipped |

## Assessment
Agents Office offers a convenient local interface for running a team of agents with scheduled routines. The reviewed
version gives these agents broad reach: they inherit all connected services of the user, can act without the user being
present, and their stored outputs are fed back into later prompts. Protection against misuse by untrusted content or
other local processes is thin. The project is a beta and its license restricts commercial use. The risks are serious
for any machine that holds real mail, calendar or browser sessions.

## Main risks
- Agents receive access to every connected service and, by default, the user's signed-in browser.
- Scheduled routines act autonomously, so a manipulated input can trigger actions unattended.
- Stored results and learned rules are reused as prompt input, which allows persistent manipulation.
- The local interface has limited protection against other processes or web pages on the same machine.
- A stored login token is read for a usage display and sent to a vendor endpoint that is not publicly documented.
- Licensing is non-commercial and has extra terms, which limits use in a company.

## Recommendation
Do not use the reviewed version on a machine with real accounts. Anyone who still wants to evaluate it should do so
only in a disposable, isolated environment with no real credentials and with the browser integration and unattended
routines switched off. A later upstream release may change this picture and would need its own review.

---
*Static review of the version named above; no guarantee, later versions may differ. Process: see the [project README](../../README.md).*
