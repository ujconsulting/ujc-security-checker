<!-- source: README.md sha256:af6184ff33da42f901831ba007992ad4ee24aefd042a03bbb4a0a75640f387d6 -->
[English](README.md) | [Deutsch](README_de.md)

# graphify - Kurzfassung der Prüfung

| | |
|---|---|
| Was | Baut aus einem Code-Repository einen abfragbaren Wissensgraphen und stellt ihn Coding-Agenten bereit |
| Art | Python-Paket mit Kommandozeilenprogramm, MCP-Server und erzeugten Skills für viele Agenten-Plattformen |
| Upstream | `Graphify-Labs/graphify` - Lizenz Apache-2.0 |
| Geprüfte Version | Tag `v0.9.76` = `0010e25d0d983bc127cef0ee0f7e490bed74e44c` |
| Geprüft am | 04.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (Erstaudit durch Codex; Erstaudit durch Claude inhaltlich gleich) |
| Empfehlung | nur unter Bedingungen einsetzen |

## Bewertung
graphify hält, was es verspricht: Es liest Quellcode in vielen Sprachen und erzeugt einen Graphen, den Agenten abfragen
können, was viel Leseaufwand spart. Das veröffentlichte Paket stimmte mit dem getaggten Quellcode überein. Die
Hauptbedenken betreffen die Selbstinstallation: Standardmäßig ändert es die Agenten-Konfiguration global, ergänzt Hooks
und lässt Skills weitere Software nachinstallieren. Ist die Dokumentanalyse aktiviert, kann es aus bereits vorhandenen Zugangsdaten automatisch einen externen
Sprachmodell-Dienst vor einem lokalen Modell wählen und Dokumentinhalte dorthin senden. Die Befunde sind beherrschbar, wenn der Installationsumfang begrenzt wird. Eine Korrektur der
offenen Punkte durch Upstream war zum Zeitpunkt der Prüfung nicht zu finden.

## Hauptrisiken
- Der Installer ändert standardmäßig die globale Agenten-Konfiguration; Git-Hooks sind optional.
- Skills können zur Laufzeit eine Selbstinstallation oder ein Update auslösen.
- Die optionale Analyse von Dokumenten und Bildern sendet Inhalte an externe Modellanbieter.
- Erzeugte Graph-Ausgaben und ihre Anweisungen werden von Agenten wieder gelesen und können nicht vertrauenswürdigen Text enthalten.
- Viele plattformspezifische Skills vergrößern den Codeumfang, der das Agentenverhalten verändert.

## Empfehlung
Vertretbar für Leser, die es pro Projekt statt global installieren, prüfen, was der Installer schreibt, Hooks und
Selbstaktualisierung ausgeschaltet lassen und bei sensiblen Repositories nur lokale Analyse nutzen. Ohne diese
Bedingungen gewährt die Standardeinrichtung mehr Reichweite, als ein Code-Graph-Werkzeug braucht.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
