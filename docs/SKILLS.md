[English](SKILLS.md) | [Deutsch](SKILLS_de.md)

# Skills

The project skills live in `.claude/skills/<name>/`. Claude Code and Codex load only `SKILL.md`
(Codex through the generated mirror in `.agents/skills/`, `python tools/codex_skills_sync.py`).
Next to it, `README.md` and `README_de.md` are short docs for humans. `SKILL.md` is
authoritative; if a README and the skill disagree, the skill wins.

| Skill | Purpose | When | Main commands |
|---|---|---|---|
| [`tool-review`](../.claude/skills/tool-review/README.md) | the whole review process of an external tool, from intake to maintenance | a new tool, a patch round, a final test, an upstream update | `tools/scan.sh`, `python tools/codex_ro.py`, `tools/cr_full_review.sh`, `tools/container_test_*.sh`, `tools/behavior_probe.sh` |
| [`usage-analysis`](../.claude/skills/usage-analysis/README.md) | where a tool helps in your projects and where not, incl. an autonomy rating | step 7 of the review, "is it worth it?" | none; result in `private/repos/<name>/usage-analysis.md` |
| [`finding-disclosure`](../.claude/skills/finding-disclosure/README.md) | report findings upstream with policy check, approval and register; watch answers, inbox and mailbox | findings go upstream; answers or fixes; own repository becomes public | `tools/disclosures/channel.py`, `approval.py`, `issue_submit.py`, `advisory_submit.py`, `mail_report.py`, `register.py`, `disclosure_watch.py` |
| [`mcp-build`](../.claude/skills/mcp-build/README.md) | house rules for own and third-party MCP servers | build, adopt or register an MCP server | none (technology from `anthropic-skills:mcp-builder`) |
| [`sandbox-setup`](../.claude/skills/sandbox-setup/README.md) | set up, check, rebuild, remove the sandbox | first setup, before a scan or container run, after errors | `tools/setup.sh [--check \| --rebuild \| --remove]` |
| [`docker-sandbox`](../.claude/skills/docker-sandbox/README.md) | rules and pattern for throwaway containers that run third-party code | container tests, behavior probe, new container scripts | `tools/container_test_python.sh`, `tools/container_test_npm.sh`, `tools/behavior_probe.sh` |
| [`proxmox-lxc-sandbox`](../.claude/skills/proxmox-lxc-sandbox/README.md) | throwaway LXC on Proxmox when Docker is not enough | systemd, services, long runs, network behavior over time | `pct create/snapshot/exec/destroy` (each block after approval) |

## How the skills fit together

```text
tool-review  --step 7-->  usage-analysis
     |  step 4 / 11 / 11b
     +--> sandbox-setup --> docker-sandbox --(not enough)--> proxmox-lxc-sandbox
     |  MCP server as target
     +--> mcp-build
     |  step 14
     +--> finding-disclosure
```

## Rules that apply to every skill

- Nothing from a reviewed tool is installed or executed without the owner's approval.
- Nothing leaves the machine (push, issue, advisory, mail) without an explicit instruction.
- Operation-specific details live in the gitignored `private/`; the skills say "if present, read
  `private/<file>`".
- After changing a skill: `python tools/codex_skills_sync.py`, update its `README.md` and
  `README_de.md`, then `python tools/public_check.py --stamp .claude/skills/<name>/README.md
  .claude/skills/<name>/README_de.md` and `python tools/public_check.py` (exit 0).
