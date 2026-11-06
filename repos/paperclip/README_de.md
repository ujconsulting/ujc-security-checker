<!-- source: README.md sha256:48a005e5e76fe9f5ffdfaa2b2b1fe705ebfb80ef3a25138dc3d54f9403117c54 -->
[English](README.md) | [Deutsch](README_de.md)

# paperclip - Kurzfassung der Prüfung

| | |
|---|---|
| Was | Selbst gehosteter Server mit Weboberfläche, der "Firmen" aus KI-Agenten mit Aufgaben, Budgets, Freigaben und Routinen steuert |
| Art | npm-Pakete (CLI, Server, Adapter), TypeScript-Monorepo, Docker-Image |
| Upstream | `paperclipai/paperclip` - Lizenz MIT |
| Geprüfte Version | Tag `v2026.1005.0` = `467125fafb47a8520856504fecc48d6e32055db1` |
| Geprüft am | 10.10.2026 (Codex-Audit 12.10.2026) |
| Urteil | `DO NOT USE` (Erstaudit durch Codex; Erstaudit durch Claude stimmt zu: mit den Standardeinstellungen nicht brauchbar) |
| Empfehlung | mit Standardeinstellungen nicht einsetzen |

## Bewertung
Paperclip ist eine ehrgeizige Steuerungsebene für viele Agenten mit nützlichen Governance-Ideen wie Budgets und
Freigaben. In der geprüften Version sind Agenten jedoch standardmäßig großzügig berechtigt, der lokale Modus verhält
sich wie ein impliziter Administrator, und Plugins lassen sich zur Laufzeit nachinstallieren. Zum Zeitpunkt der Prüfung
gab es mehrere veröffentlichte Sicherheitshinweise und weitere offene Meldungen; die meisten Befunde der Prüfung waren
Upstream bereits bekannt und ohne Korrektur. Telemetrie und Update-Prüfung sind standardmäßig aktiv. Beide Prüfer
kamen zum gleichen Ergebnis.

## Hauptrisiken
- Agenten laufen als Kindprozesse des Server-Benutzers und sind standardmäßig großzügig berechtigt.
- Der lokale Modus gewährt implizite Administratorrechte, die andere Schutzmaßnahmen des Rechners aushebeln können.
- Zur Laufzeit installierte Plugins laufen als Code in der Server-Umgebung.
- Nicht vertrauenswürdige Inhalte wie E-Mails können Agenten mit Shell-Zugriff erreichen.
- Mehrere bekannte Schwachstellen waren ohne Korrektur von Upstream offen.
- Telemetrie, Ankündigungen und Update-Prüfungen kontaktieren standardmäßig externe Dienste.

## Empfehlung
Nicht auf einer Arbeitsstation oder mit echten Zugangsdaten einsetzen. Allenfalls in einem eigenen, isolierten
Gastsystem mit Snapshots, eigenem Netzsegment, ohne echte Geheimnisse und ohne E-Mail-Anbindung erproben, nachdem auf
authentifizierten Modus umgestellt, großzügige Standardwerte und Telemetrie abgeschaltet und Geheimnisse außerhalb der
Reichweite der Agenten gehalten wurden.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
