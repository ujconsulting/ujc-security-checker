<!-- source: README.md sha256:f8f53105bf208f378327cf7a9c2e48fd4519a5ebe0666ea0669cc7e7410a4517 -->
[English](README.md) | [Deutsch](README_de.md)

# oh-my-claudecode - Kurzfassung der Prüfung

| | |
|---|---|
| Was | Orchestrierungs-Plugin für Claude Code mit spezialisierten Agenten, Skills, Schlüsselwort-Auslösern, Hooks und einem MCP-Server |
| Art | Claude-Code-Plugin mit npm-Paket; gebaute Bundles liegen im Repository |
| Upstream | `Yeachan-Heo/oh-my-claudecode` - Lizenz MIT |
| Geprüfte Version | Tag `v5.6.1` = `13543f9d6fc1a13a15b68fe5c97baeb3268569e2` |
| Geprüft am | 04.10.2026 |
| Urteil | `DO NOT USE` (Erstaudit durch Codex; Urteilszeile des Claude-Erstaudits nicht erhalten) |
| Empfehlung | in der ausgelieferten Form nicht einsetzen |

## Bewertung
Das Plugin bündelt viele nützliche Workflow-Funktionen: Agenten für Planung, Review und Verifikation, dauerhafte
Notizen und mehrere autonome Modi. Genau diese Breite ist das Problem. Es registriert viele Hooks auf nahezu jedes
Ereignis, liefert große vorgebaute Bundles aus, die nur stichprobenartig gegen den Quellcode geprüft wurden, und
enthält eine automatische Berechtigungsentscheidung, die manche Befehle weiter freigibt, als ein Nutzer erwartet.
Mehrere Befunde wurden an Upstream gemeldet. Insgesamt räumt die geprüfte Version dem Plugin mehr Befugnis über den
Rechner des Nutzers ein, als sich rechtfertigen lässt.

## Hauptrisiken
- Ein Berechtigungs-Hook kann Befehle anhand grober Mustervergleiche automatisch freigeben.
- Autonome Modi und Team-Modus können ohne menschliche Kontrolle breit committen oder Dateien ändern.
- Hooks lesen und schreiben Agenten-Zustand und Einstellungen, auch an Stellen, die Zugangsdaten enthalten können.
- Gebaute Bundles im Repository lassen sich schwer gegen den lesbaren Quellcode prüfen.
- Globaler Installer und Updater verändern die Umgebung des Nutzers über das Plugin hinaus.
- Benachrichtigungs- und Statusfunktionen kontaktieren externe Dienste.

## Empfehlung
Die geprüfte Version nicht einsetzen. Wer ähnliche Abläufe möchte, nimmt besser kleinere Werkzeuge mit schmalem
Hook-Umfang oder erprobt dieses nur in einer isolierten Umgebung mit abgeschaltetem Berechtigungs-Hook und
abgeschalteten autonomen Modi. Eine spätere Version bräuchte eine neue Prüfung.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
