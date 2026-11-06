---
name: usage-analysis
description: Analyses where a reviewed external tool helps in the owner's projects and where not, and writes the result to private/repos/<name>/usage-analysis.md (private, it names the owner's projects). Reads the owner's portfolio (if present, private/context/portfolio.md) and, if needed, the CLAUDE.md of candidate projects; assigns use case, benefit, effort, data class/risk and recommendation per project, names excluded areas and overlaps with existing tools. A fixed section 6 'Autonomous agentic work' rates how far the tool carries largely autonomous analysis, planning, programming, testing and evidence by agents (per phase, loop closure, sandbox model, GUI automation, risks, rating). Use when - (1) tool-review step 7 is reached, (2) someone asks where a tool helps or whether it is worth it, (3) an analysis needs updating after a new round or upstream update, (4) someone asks how autonomously an agent can work with a tool.
---

# usage-analysis - where the tool helps and where it does not

Result: `private/repos/<name>/usage-analysis.md` from the template
`templates/usage-analysis.md` (the result is private and gitignored - it names the
owner's own projects, hosts and data classes; a local variant in `private/templates/` wins if present). The analysis justifies the scope of use against
which the threat model is defined in `tool-review` step 8 - so it comes **before** the decision,
not afterwards as advertising copy.

The public summary `repos/<name>/README.md` says nothing about own use; the analysis stays private.

## Input

- The tool: purpose, functions, way of working (local/cloud, which models, which files it reads
  and writes), limits - from the local record `private/records/<name>/`, the reviews and, for a fork,
  `UJC-PATCHES.md` (section "Scope of use and threat model") and `docs/ujc/UJC-USAGE.md`.
- The reviewed or hardened state and the last verdict.

## Sources about the owner's projects

**If present, read `private/context/portfolio.md` first.** It holds what this public skill does
not name: the prioritised work areas, the location of the project atlas, the context-of-use
table, the infrastructure table for section 6, the reference project and further own skills and
knowledge bases. Then, in this order:

1. The prioritised work areas and the cluster relations (location: `portfolio.md`).
2. The project atlas - one page per domain with one-line project descriptions, state,
   technology; foreign clones are an excluded area.
3. If needed, the `CLAUDE.md` (and `AGENTS.md`) of a candidate project - read only, to make the
   use case concrete (language, size, existing tools, data classes).
4. Do not open: customer folders, `.env*`, finance folders, folders with plain-text credentials
   (the concrete list is in `portfolio.md`). For the analysis it is enough to know that they exist.
   **Exception section 6:** the infrastructure table in `portfolio.md` is usually enough. If it is
   outdated, read only the guest overviews named there and take over **only** host names, VMIDs
   and roles - no IP addresses, accounts, keys, paths to key files.

Atlas entries are snapshots; if in doubt about the state of a project, `git -C <project> log -1`.

## Procedure

1. **The tool in your own words** (section 1): what it does and what it does not, without
   marketing; the limits of the reviewed state (locks, approval variables) explicitly.
2. **Collect candidates**: for each prioritised work area ask "which recurring activity there
   would the tool shorten, improve or secure?" Be concrete - not "understand code", but e.g.
   "find dependencies between application metadata and SQL views before a view is changed".
3. **Usage matrix** (section 2), per row:
   - **Measurable benefit** where possible: minutes per task, hits, tokens/context, an error
     class that goes away. Mark estimates as estimates.
   - **Effort**: S/M/L for setup and ongoing maintenance (fork updates count).
   - **Data class**: own data / customer data / personal data / secrets - and whether content
     leaves the machine (cloud). Customer data + cloud without approval = "no".
   - **Recommendation**: use / test (pilot) / no.
4. **Excluded areas** (section 3) with reason: at least foreign clones, customer folders, secret
   folders; plus everything the tool's threat model excludes.
5. **Overlaps** (section 4): compare with existing tools and say honestly whether the tool adds
   value or duplicates. Typical comparison partners:
   - Codex as a read-only counter-reviewer via `tools/codex_ro.py`, the wrapper from [claudex-loop](https://github.com/ujconsulting/claudex-loop) (plan, audit and code reviews)
   - superpowers skills (brainstorming, writing-plans, subagent-driven-development, TDD, debugging)
   - the owner's own skills and knowledge bases (list in `portfolio.md`)
   - existing infrastructure such as a local RAG/graph stack (list in `portfolio.md`)
6. **Recommendation and next steps** (section 5): one sentence recommendation; pilot project
   with a metric and an abort criterion; prerequisites (approval, installation, configuration).
   One line points to the autonomy rating (6.7) if it shifts the recommendation.
7. **Autonomous agentic work** (section 6, mandatory): following the analysis part below.

## Context of use

The owner's context of use (work areas, typical work, data classes) is a table in
`private/context/portfolio.md` and serves as the review grid. Generic baseline, if the file is
missing: ask the owner for the context (platform, agent tooling, parallel sessions per
repository, guard hooks, technologies, data classes).

## Analysis part "Autonomous agentic work" (section 6)

Requirement of the owner of 10.10.2026: look at every reviewed tool also with regard to how far it
carries **largely autonomous** analysis, programming and testing by agents - so that a human is
involved only at a few, deliberately chosen points. The yardstick is a real development project
(the reference project in `portfolio.md`), including the parts that today need a hand on the
GUI of a Windows desktop application.

The question is not "can the tool do a lot on its own", but: **which human touch point goes away,
and how does the agent itself recognise that its result is correct?** A tool that produces code
faster but leaves the check to the human shifts work instead of taking it off.

### Two environments - always rate them separately

| | **E - developer machine** | **A - autonomy environment** |
|---|---|---|
| What | every developer machine with its agent tooling and development services | isolated guests (VM), built specifically for unattended agent runs |
| Credentials | real ones: password vault, code hosting, ticket system, model accounts | **none** for production systems; only own, limited keys (model API with a spending limit, a Git token for exactly one repository, push only to work branches) |
| Data | own data + third-party data | own code, a copy of a demo database, self-generated test documents - **no** third-party data |
| Network | local network, internet | own network segment, egress only to a list (model APIs, package mirrors); no route to the local network, production systems or write access to code hosting |
| Reset | not possible (real workstation) | snapshot "clean" per guest, rollback before every run/scenario |
| Protection comes from | guard hooks, `permissions.deny`, hardening of the tool, discipline | **structure**: what the environment cannot reach, no agent can damage; hooks only as a second line |
| Threat model | the checker's (`templates/threat-model.md`), decided per tool | its own model "A", still to be decided - section 6.3 of every analysis provides the template for it |

⛔ **Principle for A:** a function locked on E does not become admissible in A because the
analysis suggests it. It needs its own scope-of-use decision by the owner (threat model "A") and -
like every installation - the owner's approval. The analysis only says **whether it would be
worth it and which findings also apply in A**. Findings that were only caught by hooks or
discipline still apply in A if the tool bypasses the hooks or the environment can reach the
damage (push target, model key, repository content, spending limit).

### Existing building blocks (October 2026)

| Building block | Contribution to autonomy | Limit |
|---|---|---|
| [claudex-loop](https://github.com/ujconsulting/claudex-loop) (`plan-review`, `build`, `code-review`, `audit`; read-only Codex via `tools/codex_ro.py`) | Codex as an independent, read-only counter-reviewer; machine-readable verdicts (`VERDICT:`) | quota: one run per window; exit 3 = the review did not happen |
| superpowers (`writing-plans`, `subagent-driven-development`, `test-driven-development`, `systematic-debugging`, `verification-before-completion`) | working discipline for long runs: test first, then code, evidence before "done" | instructions to the model, no technical lock |
| `ralph-loop` (official plugin) | a stop hook feeds the same task again until a completion promise arrives; `--max-iterations` | "done" is a claim of the model, not evidence - needs an external check criterion |
| Claude Code headless (`claude -p`), sub-agents, worktrees | unattended runs, parallel subtasks | without a sandbox all of the user's permissions apply |
| Codex CLI | second model; read-only in the wrapper `codex_ro.py` | as a builder only in a deliberate swapped-roles workflow |
| Playwright MCP **headless** | web interfaces without a visible browser | - |
| Claude in Chrome / plugin Playwright | - | **not for agents**: occupies a shared, visible browser profile |
| Computer use (Claude desktop app) | see the screen, click, type - for desktop programs without an automation interface | controls the desktop **on which the app runs** -> only useful *inside* the Windows guest, never on E; needs a login there |
| `superpowers-lab:windows-vm` | headless Windows 11 VM via Docker (`dockur/windows`), SSH | needs KVM (`/dev/kvm`) -> a Linux host with KVM, not Docker Desktop on Windows |
| Container scripts of the checker (`tools/container_test_*.sh`) | pattern for isolation: `git archive`, no capabilities, network only for installation | built for package-code tests, not for long agent runs |
| Sandboxes of the checker (skills `docker-sandbox`, `proxmox-lxc-sandbox`; egress proxy `tools/egress/` with an internal Docker network and a domain allowlist) | building blocks for I1/I2: internal network without LAN, exit only via an allowlist with a log, throwaway LXC with snapshot | built for review targets; for agent runs extend by model APIs, package registries only where needed |
| Domain-specific skills of the owner (list in `portfolio.md`) | evidence without a GUI: traces, logs, builds without a designer tool, SQL cross-checks | imports and printing in the business application still need the GUI |

### Infrastructure

The owner's host table (hosts, roles, suitability for A) is in `private/context/portfolio.md`, if
present - never in this public skill and never with IP addresses, accounts or key paths. Criteria
for a host for A: carries nothing critical (no credential store, backups, perimeter or production
data), can host an own network segment, has snapshots.

### Reference scenario: implement a real development project as autonomously as possible

Pattern for section 6.5 of every analysis. The concrete project, its plan and its spikes are
named in `portfolio.md`. The agent works in A: a **Linux agent guest** (Claude Code, Codex,
Docker with the project's service stack, Playwright headless) and, if the project has a desktop
application part, a **Windows application guest** (the application in a development installation
with a demo database), both with snapshots.

| Stage | Who | What happens | Evidence / loop closure |
|---|---|---|---|
| **G0** environment | human, once | A guests, network segment, limited keys, application installation and licence, demo database, snapshots "clean"/"warm" | acceptance checklist of the environment |
| R1 understand | agent | plan, the knowledge base, documentation and API description of the service, schema against the demo database in the guest | list of assumptions with [B]/[I]; every [B] statement with a source |
| R2 plan | agent + Codex | recon, plan, Codex plan review via `tools/codex_ro.py` until `APPROVED` | review log |
| **G1** plan | human | approval of the plan and of all [A] decisions; stays human: business decisions, legal/tax rules, price/licence | - |
| R3 spikes | agent | attack catalogue as tests against the stack; restart of worker/queue; deep links via Playwright; the GUI-bound steps of the application with snapshot rollback in between | per spike: logs, traces, cross-checks against the database and service API, screenshots -> matrix in the spike notes |
| R4 program | agent | per plan step `test-driven-development` + `subagent-driven-development` **or** swapped roles (Codex builds, Claude checks) | tests red -> green; commits in A are free (no review bot there), push only to a Git work branch |
| R5 test | agent | unit (fakes) -> integration against the stack -> end-to-end through the application with a rollback per scenario; attack catalogue as a regression gate | test reports (JUnit/JSON), evidence folder per run |
| R6 verify | agent + Codex | Codex code review (DoD, quality, security, docs, tests) via `tools/codex_ro.py` with an exposure pass; `verification-before-completion` | verdicts, evidence folder with a manifest (commit, snapshot, time) |
| **G2** functional acceptance | human | reads report and evidence folder, spot check live in the guest | - |
| **G3** publish | human | push to GitHub, PR, merge (merge gate), production signature, delivery | - |
| R8 operate | agent (development only) | update gate: documentation check -> new service image in the stack -> attack catalogue -> report | report; **no** autonomous operation outside development |

Every negative spike result with an abort criterion (e.g. an application event does not fire in
the web client) leads back to G1 - the agent does not change the plan by itself.

### GUI automation in Windows - ranking and pitfalls

1. **Without a GUI wherever possible:** SQL against the demo database, log files, REST APIs,
   builds without the designer tool. The GUI is only the trigger, not the evidence.
2. **Web client** of the application server: Playwright headless from the Linux guest - check
   whether output and preview behave the same in a headless browser.
3. **Desktop client, administration, import of extensions:** UI Automation (pywinauto with
   `backend="uia"`, fallback `win32`; AutoHotkey only for key sequences without a UIA tree),
   driven by automation IDs and window titles, never by coordinates; wait for window states
   instead of `sleep`.
4. **Computer use** only for the unforeseen (error dialog, first encounter with a form) and to
   explore click paths - which are then fixed as a UIA script. Only the script is deterministic
   and repeatable.

Pitfalls: UI automation needs an **interactive desktop session** - processes started via SSH or
WinRM see no desktop. Remedy: autologon of a local test user in the guest and a small GUI bridge
that runs in that session and accepts jobs (action, screenshot, window list) via an SSH tunnel
from the Linux guest. A minimised RDP session stops rendering - use the hypervisor's console
session instead of RDP. Evidence per step from at least two sources: a screenshot shows only
what is visible; the effect is proven by trace/log, SQL cross-check and the target system.

### Missing infrastructure (base list - analyses refer to the numbers)

| No. | What is missing | Effort |
|---|---|---|
| I1 | Own network segment for A (bridge/VLAN or internal virtual switch) with an egress list; no route to the local network or production systems, no write access to code hosting; an internal Git server only for the run's repository | M |
| I2 | Linux agent guest (VM rather than container, because of Docker in the guest and `chattr`): Claude Code, Codex CLI, uv, Docker, Playwright headless; its own `~/.claude` with mirrored rules and guards; model key with a spending limit | M |
| I3 | Windows application guest without a domain: the application in the required version(s), desktop and web client, administration, a database server (developer edition) with a copy of the demo database, local test user, OpenSSH, snapshots "clean"/"warm"; clarify the application licence for a development instance | L |
| I4 | GUI bridge in the interactive session (autologon, pywinauto/UIA, screenshot, window list) - alternatively the Claude desktop app with computer use in the guest | M |
| I5 | Snapshot control outside the agent's reach: a fixed command list (rollback, start, stop) or a hypervisor API token with a role only for these guests | S-M |
| I6 | Evidence collector per run: application trace and debug log on, own log table, SQL cross-checks, service API, screenshots -> evidence folder with a manifest | S-M |
| I7 | Run brake: budget per run (iterations, run time, cost), repetition detection, Codex quota, abort report | S |
| I8 | Build/signing chain in the guest with a development certificate; if the production signature needs a secret key, it stays at G3 | S-M |
| I9 | Repository flow: clone from the internal Git server, a work branch per run, push only there; transfer to GitHub by the owner | S |
| I10 | Decision which test data may go into A and to model APIs (demo databases yes; database copies of other origin no) | S |
| I11 | Observation: logs of the A guests to a central collector, alarm on an egress violation or a budget overrun | S |

### The seven questions per tool (section 6 of the analysis)

1. **6.1 Contribution per phase** - understand (code, docs, DB schema, decompiled code), plan,
   program, test (unit, integration against development stacks, GUI/E2E), verify/prove,
   operate: what does the tool take over, which human touch point goes away or gets shorter,
   what stays with the human (decisions, approvals, functional acceptance). "None" is a valid
   answer.
2. **6.2 Loop closure** - can an agent check its own result with the tool (test, measurement,
   evidence)? Deterministic, headless, repeatable, machine-readable? Distinguish *check*
   (external criterion) from *claim* (the model reports "done").
3. **6.3 Permission and sandbox model** - which permissions does the tool need for autonomous
   work; rate every function locked on E individually for A: benefit in A, findings from the
   audit that **still apply** in A (and why), condition for admission in A.
4. **6.4 Computer use / GUI** - does the tool need or provide GUI interaction? What of it works in
   a Windows guest following the ranking above; which numbers of the base list (I1-I11) does it
   require?
5. **6.5 Place in the reference scenario** - per stage (G0-R8): does it help, and how?
6. **6.6 Risks of autonomous work** - prompt injection (repository, web, **document content/OCR**),
   cost and quotas, uncontrolled loops, data leakage, bypassing guards, false evidence - each
   with a countermeasure.
7. **6.7 Rating** - autonomy gain **high / medium / low**, separately for E and A, each with a
   reason; plus a recommendation from the autonomy point of view (recommendation, not decision).

Standard for 6.7:

| Level | means |
|---|---|
| **high** | the tool closes a loop by itself or removes a human touch point in the reference scenario - headless, repeatable, with evidence |
| **medium** | it shortens a phase considerably, but check or evidence must come from elsewhere |
| **low** | convenience; no human touch point goes away, or existing building blocks do the same |

Duplicates count: what the Codex review via `tools/codex_ro.py`, superpowers, `ralph-loop` or Claude Code itself already
provide is not an autonomy gain of the tool.

## Limits

- The analysis is private; still **no customer names** in it if it is ever shared -
  placeholder "Customer X"; also no customer folder names that reveal a customer.
- No secrets, no paths to secret files with a description of their content.
- No trying out the tool for the analysis (installation only after approval, skill `tool-review`).
- Statements about the benefit are hypotheses until a pilot measures them - phrase them that way.
- Section 6 proposes, it does not decide: no locked function counts as admitted because of the
  analysis, not even for A. No IP addresses, accounts or key paths from the infrastructure
  documentation in the analysis.
- Nothing from `portfolio.md` goes into public files (record README, reviews, changelog).

## Completion

- The public summary `repos/<name>/README.md` is not updated with own use; keep the analysis private.
- If the base list I1-I11 changes, update it here in the skill; if the infrastructure table or the
  reference project changes, update `private/context/portfolio.md` - not only the analysis.
- Check LF/no BOM (pitfall table in `tool-review`).
