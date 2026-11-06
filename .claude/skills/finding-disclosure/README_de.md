<!-- source: README.md sha256:88c4703db2b01e543f22433749de622de0ef08866f07b0ffb51142254786d3f2 -->
[English](README.md) | [Deutsch](README_de.md)

# finding-disclosure

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Meldet Befunde aus einer Werkzeugprüfung an das Upstream-Projekt und verfolgt alles, was danach
kommt: Antworten, verknüpfte PRs, Advisories, Mails, Fristen - dazu den Eingang des eigenen
öffentlichen Repositorys und das Sicherheitspostfach. Nichts verlässt den Rechner ohne eine an den
Hash gebundene Einmal-Freigabe genau dieses Texts. Alles zu einem geprüften Repository (Register, Freigaben, Codex-Nachweise,
Berichte, Antwortentwürfe) liegt bei seinem lokalen Record (`private/records/<name>/disclosures/`); das `disclosures/` in der
Wurzel enthält nur das des Checkers selbst.

## Wann

- Befunde sollen nach upstream gemeldet werden;
- jemand fragt nach Antworten oder Fixes zu unseren Meldungen;
- im eigenen Repository oder im Postfach ist etwas eingegangen;
- ein eigenes Repository wird öffentlich (erst Private Vulnerability Reporting, dann `SECURITY.md`).

## Ablauf

1. Jeden Befund **einstufen**: kritisch (vertraulicher Kanal, Entwurf unter `private/`, Embargo)
   oder nicht kritisch (öffentliches Issue).
2. **Kanal** nur lesend ermitteln: `SECURITY.md`, Private Vulnerability Reporting, Adresse. Andere
   Code-Hosts (GitHub Enterprise, Gitea/Forgejo, GitLab, reiner Git-Server) werden in jedem Schritt
   als `<alias>:owner/name` angesprochen (Kanal, Richtlinie, Dublettensuche, Einreichung,
   Beobachtung); Gitea und reines Git haben weder PVR noch vertrauliche Issues (Adresse aus der
   `SECURITY.md`, sonst öffentliches Issue ohne Details), GitLab hat vertrauliche Issues.
3. **Richtlinienprüfung** (Pflicht): die Sicherheitsrichtlinie des Projekts vollständig lesen, als
   Nachweis ablegen, sechs Punkte je Befund bewerten (Versionen, Kanal, Pflichtinhalte,
   Geltungsbereich/„by design“, Offenlegungsregeln, Antwortfristen).
4. **Aktueller Stand und Dubletten** - trifft der Befund auf dem Standardzweig noch zu?
5. **Entwurf** aus einer Vorlage, ohne KI-Hinweis, lokale Pfade oder interne Namen. Falls in der
   `.env` eingeschaltet (Vorgabe: kritische Befunde), danach die **Befundvalidierung**
   (`FINDING: CONFIRMED` nötig; `NOT CONFIRMED` / `SEVERITY WRONG` = Code selbst prüfen, korrigieren
   oder verwerfen) und der **Exposure-Pass** (`EXPOSURE: UNSAFE/SAFE` muss zum Entwurfsfeld
   `exposure` passen; kritisch + `SAFE` braucht `exposure_override`), vor Textprüfung und Freigabe.
6. Text **zeigen und Leak-Scan**; falls in der `.env` eingeschaltet, eine **Codex-Gegenprüfung**
   jeder Aussage gegen den Upstream-Quelltext (kein Audit); dann **Freigabe**, gebunden an seinen
   SHA-256. Alle Codex-Läufe einzeln nacheinander, nie parallel; Exit 4 = Kontingent, warten.
7. **Einreichen** - immer zuerst ein Probelauf, dann mit Schalter; das Register des Records wird nachgeführt.
   Eine von Hand gesetzte Meldung (Kommentar zu einem Security Advisory) wird mit `register.py posted`
   eingetragen; ein fremdes Repository ohne Record wird abgelehnt, bevor etwas hinausgeht.
8. **Beobachten** (nur lesend) und nach der Veröffentlichung **das Embargo aufheben**. Die öffentliche
   Zusammenfassung nennt nie eine Meldung - kein Zähler, kein Datum, keine Reihenfolge.

## Befehle

```bash
python tools/disclosures/channel.py <owner/repo> --out .claudex-tmp/<name>/channel.md
python tools/disclosures/channel.py --policy <owner/repo> --out .claudex-tmp/<name>/policy.md
python tools/disclosures/approval.py show <entwurf>
python tools/disclosures/forge.py list | check <alias>      # andere Code-Hosts, <alias>:owner/name
python tools/disclosures/codex_check.py config              # wirksame Schalter, Modell/Effort
python tools/disclosures/codex_check.py finding  <entwurf> --source quarantine/<name>   # falls eingeschaltet
python tools/disclosures/codex_check.py exposure <entwurf> --source quarantine/<name>   # falls eingeschaltet
python tools/disclosures/codex_check.py run <entwurf> --source quarantine/<name>        # Textprüfung, falls eingeschaltet
python tools/disclosures/approval.py grant <entwurf> --action issue --note "<wer, wann>"
python tools/disclosures/issue_submit.py <entwurf>            # Probelauf
python tools/disclosures/issue_submit.py <entwurf> --submit
python tools/disclosures/advisory_submit.py <entwurf> [--submit]
python tools/disclosures/mail_report.py send <entwurf> [--send]
python tools/disclosures/disclosure_watch.py                 # Beobachtung, nur lesend
python tools/disclosures/register.py publish <id>            # nach der Veröffentlichung
python tools/disclosures/register.py set <id> --status answered --severity high --category injection   # setzt answered_at / fixed_at
python tools/disclosures/register.py set <id> --verification verified-fixed   # unsere Prüfung des Fix-Codes; nötig für Status fixed
python tools/disclosures/register.py migrate --record <name> [--dry-run]   # alte Wurzel-Einträge
python tools/disclosures/register.py posted <entwurf> --url <link>         # von Hand gesetzt
python tools/disclosures/own_repos_check.py                  # eigene öffentliche Repositories
```

## Beispiel

Ein nicht kritischer Fehler (die Deinstallation entfernt Hooks anderer Werkzeuge): Richtlinie
geprüft, keine Dublette, Entwurf `private/records/<name>/disclosures/N1-issue.md`, Leak-Scan sauber, der
Auftraggeber liest den Text, Freigabe mit `--action issue`, Probelauf, `--submit`. Einen Tag später
meldet die Beobachtung einen Maintainer-Kommentar „fixed in #123“ - eine Behauptung; `fixed` wird
erst gesetzt, nachdem die gemergten Dateien gelesen sind.

## Siehe auch

[`tools/disclosures/README_de.md`](../../../tools/disclosures/README_de.md),
[`disclosures/README_de.md`](../../../disclosures/README_de.md), [`SECURITY.md`](../../../SECURITY.md).
