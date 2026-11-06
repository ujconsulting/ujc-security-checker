<!-- source: README.md sha256:92bd56e7328828aade5c132212bddbe094b2fa0d59490507221f908708e3be8b -->
[English](README.md) | [Deutsch](README_de.md)

# voicestudio - review summary

| | |
|---|---|
| Was | Lokal arbeitendes Sprachstudio: Stimmklonen, Text-zu-Sprache, Transkription, Synchronisation, Diktat, mit lokaler API und Werkzeugserver-Schnittstelle |
| Art | Desktopanwendung (Electron-Hülle mit Python-Backend) sowie mobile Vorschau-Apps |
| Upstream | `debpalash/VoiceStudio` - Lizenz AGPL-3.0 (Modellgewichte haben eigene Lizenzen) |
| Geprüfte Version | Tag `v0.5.7` = `beeaae08204f0de5f49d4a087ef2b0ea8fecfcb9` |
| Geprüft am | 31.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (Claude- und Codex-Audit, gleiches Urteil) |
| Empfehlung | nur mit Auflagen einsetzen |

## Einschätzung

Die geprüften macOS-Release-Dateien stimmten mit den veröffentlichten Prüfsummen überein und die Quelldateien des
Backends mit dem Tag; das Frontend-Bundle wurde nur stichprobenartig geprüft, nicht neu gebaut. Der
Release-Prozess ist recht sorgfältig. Die Anwendung ist groß und jung und tut viel: Sie baut beim
ersten Start eine Python-Laufzeit, lädt Modelle und Engine-Komponenten aus mehreren Quellen und stellt
eine lokale API bereit, die keine eigene Authentifizierung hat. Optionale Funktionen erweitern die
Reichweite, etwa Freigabe im lokalen Netz, Hilfsagenten, die installierte Coding-Werkzeuge starten, und
Analysefunktionen auf Zustimmungsbasis. Ein direkt aus der Ferne ausnutzbarer Fehler wurde nicht
bestätigt, doch die Angriffsfläche ist breit, und mehrere Härtungsmaßnahmen fehlen. Insgesamt ist das
Risiko mittel und steigt mit jeder aktivierten optionalen Funktion.

## Hauptrisiken

- Eine lokale API und Werkzeugserver-Schnittstelle ohne Authentifizierung, die vor allem durch eine Beschränkung auf die lokale Schleife geschützt ist.
- Hilfsagenten, die installierte Assistenzwerkzeuge mit automatisch freigegebenen Änderungen und Netzzugriff starten und dabei Protokolle und Diagnosedaten verarbeiten.
- Fehlende Anwendungshärtung (keine Laufzeit-Integritätsschalter, gelockerte Bibliotheksprüfung, keine Sandbox).
- Viele Download-Quellen zur Laufzeit, teils über Drittanbieter-Proxys oder Spiegel, und nicht per Hash gesperrte Abhängigkeiten von Zusatz-Engines.
- Aufrufe von der Oberfläche ins System ohne Absenderprüfung sowie eine Freigabefunktion mit kurzer PIN ohne Ratenbegrenzung.
- Lizenz: Das Standardmodell hat eine nicht-kommerzielle Lizenz, und die Lizenzliste kennzeichnet kein Modell als kommerziell nutzbar.

## Empfehlung

Geeignet nur für Personen, die eine große, schnell veränderliche Anwendung mit breitem Netzwerk-Fußabdruck
betreiben wollen. Auf einem Einzelplatzrechner halten, Freigabe, Hilfsagenten, Analyse und optionale
Engines aus lassen, ausgehende Verbindungen auf die akzeptierten Quellen beschränken und die
Modelllizenzen vor jeder kommerziellen Nutzung prüfen. Die lokale Schnittstelle nicht für andere Nutzer
oder Netze öffnen. Die Windows-Installer waren zur Prüfung nicht codesigniert.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
