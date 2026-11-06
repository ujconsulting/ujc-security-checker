<!-- source: README.md sha256:08d16f9b5914fb3dcea420b672d72e42cf3f16682703c0e367ccf8a5631ae0cd -->
[English](README.md) | [Deutsch](README_de.md)

# .codex/ - Arbeitskontext der Codex CLI für dieses Repository

- **`../AGENTS.md`** (Repository-Root, wird von der Codex CLI automatisch geladen) ist das eigentliche
  Betriebshandbuch: Rolle als Security-Reviewer, Prüfkatalog, Sperrliste, Ergebnisformat, Aufruf-
  konventionen und die Regeln, die unter Claude Code von Hooks erzwungen werden. Codex muss **aus
  dem Repository-Root** gestartet werden, sonst lädt es die Datei nicht.
- **`../.agents/skills/`** - die Projekt-Skills für Codex, aus `.claude/skills/` erzeugt durch
  `python tools/codex_skills_sync.py`.
- **`knowledge.md`** - ein von Hand gepflegter Wissensauszug (Codex hat zwischen Sitzungen kein Gedächtnis).

Angelegt beim Aufsetzen am 10.10.2026 ohne einen Codex-Aufruf. Offen: Live-Test des
schreibgeschützten Codex-Wrappers `tools/codex_ro.py` aus [claudex-loop](https://github.com/ujconsulting/claudex-loop) (`python tools/codex_ro.py --version`, ein schreibgeschützter Aufruf) in einer Sitzung in diesem Projekt sowie der Trust-Eintrag in
`~/.codex/config.toml` (Betreiberaufgabe, hier nicht verfolgt).
