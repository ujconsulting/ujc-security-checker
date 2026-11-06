<!-- source: README.md sha256:c8449d15139a81fc7cc076c67801af95c00b8bec2d5fd966fdfb26e705792d3c -->
[English](README.md) | [Deutsch](README_de.md)

# tool-review

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Der ganze Ablauf, um ein fremdes Werkzeug (GitHub-Repository, Claude-Code-Plugin, Skill,
MCP-Server, CLI, Python- oder npm-Paket) vor dem Einsatz zu prüfen und es - wenn es sich lohnt,
aber so nicht sicher ist - als privaten, gehärteten Fork zu übernehmen. Jeder Schritt endet mit
einem Abbruchkriterium.

**Öffentliches Ergebnis = nur Zusammenfassung; eigene Fassung -> `private/repos/<name>/`.** Die
öffentliche `repos/<name>/` enthält nur eine Zusammenfassung (festgehaltene Version, Urteil,
Empfehlung, Bewertung); Audits, Prüfrunden, Recherche und Meldungsentwürfe bleiben lokal unter
`private/records/<name>/`; Fork, Patch-Runden, Endtests, Changelog und Einsatz bleiben privat.

## Wann

- ein neues Werkzeug soll geprüft werden;
- eine Patch-Runde oder ein Endtest eines Forks steht an;
- ein Fork wechselt auf ein neues Upstream-Release;
- Härtung oder Freigabe eines fremden Werkzeugs wird besprochen.

## Ablauf

1. **Aufnahme** - Zweck und geplanter Einsatz; lokale Akte `private/records/<name>/`, Zeile im
   Verzeichnis der Projekt-README (Upstream @ Version, Prüfdatum, Urteil, Empfehlung). Am Ende der
   Prüfung entsteht die öffentliche Zusammenfassung `repos/<name>/README.md` aus `templates/repo-README.md`.
2. **Quarantäne-Klon** auf festem Tag unter `quarantine/<name>/` aus beliebiger Quelle (`owner/name`,
   `<alias>:owner/name` bei einem anderen Code-Host, Git-URL, lokaler Pfad) mit `tools/quarantine_clone.py`; feststellen, was wirklich läuft
   (Manifeste, Hooks, Einstiegspunkte, Bundles).
3. **Lieferkette** - veröffentlichtes Paket gegen den Tag, Bundles gegen den Quelltext.
4. **Scanner** im Scanner-Image.
5. **Erstaudit** - derselbe Prüfauftrag an einen Claude-Sub-Agenten und an Codex; Befunde am Code
   verifiziert. Mit `claudex_audit_mode=audit|both` (Vorgabe `form`) ist die Codex-Hälfte der claudex-loop-Skill
   `/audit` auf dem Klon (Baseline unter `.claudex-tmp/<name>/audit/`, aus dem Checker-Root gestartet;
   `python tools/disclosures/codex_check.py config` zeigt Modell/Effort). Optional ein
   CodeRabbit-Vollreview (opt-in über `coderabbit_review=on`; öffentliche Repos gehen durch,
   nicht-öffentliche brauchen eine Freigabe) und weitere Zweitmeinungen.
6. **Upstream-Recherche** - Pflicht, zweimal: ein allgemeiner Durchgang vor dem Erst-Audit
   (Advisories, Security-Issues/PRs) und ein Durchgang je Befund vor seiner Bewertung (Issues und
   PRs, offen und geschlossen, jeder passende Treffer vollständig gelesen): behoben, gewollt
   („by design“), Duplikat oder neu, nützliche offene PRs.
7. **Einsatzanalyse** (Skill `usage-analysis`, privat).
8. **Entscheidung** des Auftraggebers - nicht nutzen / so nutzen / Fork härten, mit
   Bedrohungsmodell.
9. **Fork und Patch-Runden** - Klassen schließen, Unnötiges abschalten, ein Commit je Runde;
   dokumentiert nur unter `private/repos/<name>/`.
10. **Endtest** je Runde, zuerst die Befunde der Vorrunde (Ergebnis in `private/repos/<name>/reviews/`).
11. **Containertests** und **Verhaltensprobe** - nur nach Freigabe, nur im Egress-Netz
    (Ergebnis in `private/repos/<name>/reviews/`).
12. **Freigabe**, 13. **Pflege** (beide privat), 14. **Meldungen** (Skill `finding-disclosure`).
15. **Ledger** neben jedem Schritt (`tools/ledger.py`, privat): Entscheidung je Akte, jeder
    Prüflauf (Codex-Läufe über `ledger.py run codex`), Befund-Metadaten ohne Freitext.

Nie ohne Anweisung des Auftraggebers: etwas aus dem Werkzeug installieren oder ausführen, ein
Push, eine Meldung, ein Codex-Aufwand über medium, zwei Codex-Läufe gleichzeitig.

## Befehle

```bash
python tools/quarantine_clone.py <source> <name> --ref <tag-or-sha>   # owner/name, alias:owner/name, URL, path
tools/scan.sh quarantine/<name> .claudex-tmp/<name>/scan
python tools/codex_ro.py --model gpt-6.1-sol --effort medium \
    --prompt-file .claudex-tmp/<name>/codex-prompt.txt \
    --out-file .claudex-tmp/<name>/codex-initial-audit.txt \
    --err-file .claudex-tmp/<name>/codex-initial-audit-err.txt
tools/cr_full_review.sh quarantine/<name> <tag>                 # vorbereiten, zeigt Umfang + Kontingent
UJC_CR_YES=1 tools/cr_full_review.sh quarantine/<name> <tag>    # nach Ankündigung
UJC_TEST_APPROVAL=<fork-sha>[+<upstream-sha>] tools/container_test_python.sh <fork> <ref> <upstream-tag> <extras>   # nach Freigabe
UJC_PROBE_APPROVAL=<commit-sha> tools/behavior_probe.sh quarantine/<name> <ref> '<einstiegspunkt>'   # standardmaessig offline; UJC_PROBE_ONLINE=1 behaelt das Netz
python tools/ledger.py run codex --record <name> --round <NN> --step final-test --commit <sha> -- <codex_ro.py-Argumente>
python tools/ledger.py finding add --record <name> --id r<NN>-<id> --severity high --category injection --status open
python tools/ledger.py check
```

## Beispiel

Ein Python-Plugin soll in mehreren Projekten laufen: Aufnahme mit Zweck, Quarantäne-Klon auf
`v1.2.3`, Wheel geladen und mit dem Tag verglichen („identisch“), Scanner ohne nennenswerte
Treffer, Claude und Codex melden beide einen Befund zu einer automatischen Update-Prüfung.
Entscheidung „Fork härten“: die Update-Prüfung wird am Einstiegspunkt abgeschaltet, der Endtest
bestätigt das, `FINAL TEST: APPROVED`, Containertests nach Freigabe, Freigabe.

## Siehe auch

[`docs/SKILLS_de.md`](../../../docs/SKILLS_de.md), [`tools/README_de.md`](../../../tools/README_de.md),
[`templates/`](../../../templates/), [`AGENTS.md`](../../../AGENTS.md) (Codex als Reviewer).
