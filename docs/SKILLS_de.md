<!-- source: SKILLS.md sha256:5494f37b2288ad08ebd22a25593e9464f9c9c35bcc638787ef4e7c6e492b93cf -->
[English](SKILLS.md) | [Deutsch](SKILLS_de.md)

# Skills

Die Projekt-Skills liegen in `.claude/skills/<name>/`. Claude Code und Codex laden nur `SKILL.md`
(Codex über den erzeugten Spiegel in `.agents/skills/`, `python tools/codex_skills_sync.py`).
Daneben sind `README.md` und `README_de.md` kurze Dokus für Menschen. Maßgeblich ist `SKILL.md`;
widersprechen sich README und Skill, gilt der Skill.

| Skill | Zweck | Wann | Wichtigste Befehle |
|---|---|---|---|
| [`tool-review`](../.claude/skills/tool-review/README_de.md) | der ganze Prüfablauf eines fremden Werkzeugs, von der Aufnahme bis zur Pflege | ein neues Werkzeug, eine Patch-Runde, ein Endtest, ein Upstream-Update | `tools/scan.sh`, `python tools/codex_ro.py`, `tools/cr_full_review.sh`, `tools/container_test_*.sh`, `tools/behavior_probe.sh` |
| [`usage-analysis`](../.claude/skills/usage-analysis/README_de.md) | wo ein Werkzeug in Ihren Projekten hilft und wo nicht, mit Autonomie-Bewertung | Schritt 7 der Prüfung, „lohnt es sich?“ | keine; Ergebnis in `private/repos/<name>/usage-analysis.md` |
| [`finding-disclosure`](../.claude/skills/finding-disclosure/README_de.md) | Befunde mit Richtlinienprüfung, Freigabe und Register nach upstream melden; Antworten, Eingang und Postfach beobachten | Befunde gehen nach upstream; Antworten oder Fixes; eigenes Repository wird öffentlich | `tools/disclosures/channel.py`, `approval.py`, `issue_submit.py`, `advisory_submit.py`, `mail_report.py`, `register.py`, `disclosure_watch.py` |
| [`mcp-build`](../.claude/skills/mcp-build/README_de.md) | Hausregeln für eigene und fremde MCP-Server | MCP-Server bauen, übernehmen oder registrieren | keine (Technik aus `anthropic-skills:mcp-builder`) |
| [`sandbox-setup`](../.claude/skills/sandbox-setup/README_de.md) | Sandbox einrichten, prüfen, neu bauen, entfernen | Ersteinrichtung, vor einem Scan oder Containerlauf, nach Fehlern | `tools/setup.sh [--check \| --rebuild \| --remove]` |
| [`docker-sandbox`](../.claude/skills/docker-sandbox/README_de.md) | Regeln und Muster für Wegwerf-Container, die fremden Code ausführen | Containertests, Verhaltensprobe, neue Container-Skripte | `tools/container_test_python.sh`, `tools/container_test_npm.sh`, `tools/behavior_probe.sh` |
| [`proxmox-lxc-sandbox`](../.claude/skills/proxmox-lxc-sandbox/README_de.md) | Wegwerf-LXC auf Proxmox, wenn Docker nicht reicht | systemd, Dienste, lange Läufe, Netzverhalten über Zeit | `pct create/snapshot/exec/destroy` (jeder Block nach Freigabe) |

## Wie die Skills zusammenhängen

```text
tool-review  --Schritt 7-->  usage-analysis
     |  Schritt 4 / 11 / 11b
     +--> sandbox-setup --> docker-sandbox --(reicht nicht)--> proxmox-lxc-sandbox
     |  MCP-Server als Prüfobjekt
     +--> mcp-build
     |  Schritt 14
     +--> finding-disclosure
```

## Regeln, die für jeden Skill gelten

- Nichts aus einem geprüften Werkzeug wird ohne Freigabe des Auftraggebers installiert oder
  ausgeführt.
- Nichts verlässt den Rechner (Push, Issue, Advisory, Mail) ohne ausdrückliche Anweisung.
- Betriebsspezifisches liegt im gitignorierten `private/`; die Skills sagen „falls vorhanden,
  `private/<datei>` lesen“.
- Nach einer Skill-Änderung: `python tools/codex_skills_sync.py`, dessen `README.md` und
  `README_de.md` nachziehen, dann `python tools/public_check.py --stamp .claude/skills/<name>/README.md
  .claude/skills/<name>/README_de.md` und `python tools/public_check.py` (Exit 0).
