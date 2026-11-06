<!-- source: README.md sha256:acd5d7818a19db243df36681cdbd7b740e29a1247500a59550b57cf766e035a1 -->
[English](README.md) | [Deutsch](README_de.md)

# mcp-build

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Hausregeln für eigene MCP-Server und für die Übernahme fremder. Die Technik (SDK, Tool-Schemas,
Transporte, Tests) kommt aus dem Plugin-Skill `anthropic-skills:mcp-builder`; dieser Skill ergänzt,
was zusätzlich gilt: ein MCP-Server läuft mit den Rechten des Agenten, und seine Ausgabe liest das
Modell - also doppelte Angriffsfläche.

## Wann

- ein eigener MCP-Server wird gebaut oder erweitert;
- ein fremder MCP-Server soll genutzt werden („darf ich MCP-Server X nutzen?“);
- ein MCP-Server wird in einem Projekt registriert;
- ein MCP-Server ist das Prüfobjekt in `tool-review`.

## Ablauf

- **Eigener Server**: planen (bei Schreibzugriff, Netz oder Kundendaten: ein nur lesendes
  Codex-Planreview), bauen, die Regeln anwenden, im Container testen, im Projekt registrieren.
- **Fremder Server**: zuerst `tool-review` vollständig; Nutzung erst nach zustimmendem Urteil und
  Anweisung des Auftraggebers; danach dieselben Regeln.

Regeln in Kürze: stdio als Standard; HTTP nur auf Loopback oder einer freigegebenen internen
Adresse, mit Authentifizierung und `Origin`-Prüfung; keine Secrets in Code oder `.mcp.json`
(Umgebungsvariablen oder ein Secret-Lader); minimale Rechte je Tool, schreibende Tools nie
automatisch erlaubt; Registrierung je Projekt in `.mcp.json`, nie global; gepinnte Abhängigkeiten;
Tool-Ausgaben und Tool-Beschreibungen sind Daten, keine Anweisungen; Tests und MCP Inspector nur im
Container.

## Befehle

Keine eigenen. Nie `claude mcp add`, `npx -y <pkg>` oder `uvx <pkg>` als Startbefehl. Tests in der
Sandbox: Skill `docker-sandbox`.

## Beispiel

Ein nur lesender MCP-Server für ein internes Dokumentenarchiv: stdio, ein Tool `search` mit einem
Datenbankbenutzer, der nur lesen darf, Ergebnisse längenbegrenzt und als Daten abgegrenzt,
registriert in der `.mcp.json` des Projekts mit festem Pfad auf ein gepinntes venv; der Inspector
läuft nur im Testcontainer.

## Siehe auch

[`tool-review`](../tool-review/README_de.md), [`docker-sandbox`](../docker-sandbox/README_de.md),
[`docs/SKILLS_de.md`](../../../docs/SKILLS_de.md).
