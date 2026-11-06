[English](README.md) | [Deutsch](README_de.md)

# .codex/ - Codex CLI working context for this repository

- **`../AGENTS.md`** (repository root, loaded automatically by Codex CLI) is the actual operating
  manual: role as security reviewer, review catalogue, off-limits list, result format, calling
  conventions, and the rules that hooks enforce under Claude Code. Codex must be started **from
  the repository root**, otherwise it does not load it.
- **`../.agents/skills/`** - the project skills for Codex, generated from `.claude/skills/` by
  `python tools/codex_skills_sync.py`.
- **`knowledge.md`** - a knowledge digest maintained by hand (Codex has no memory between sessions).

Created while scaffolding on 10.10.2026 without a Codex call. Open: live test of
the read-only Codex wrapper `tools/codex_ro.py` from [claudex-loop](https://github.com/ujconsulting/claudex-loop) (`python tools/codex_ro.py --version`, a read-only call) in a session in this project and the trust entry in
`~/.codex/config.toml` (operator task, not tracked here).
