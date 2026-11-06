<!-- source: README.md sha256:3925ff4b4cf8c1e4868602d206d588c6ca2f7d241052ff0ace8a82af6c217688 -->
[English](README.md) | [Deutsch](README_de.md)

# openwhispr - review summary

| | |
|---|---|
| Was | Desktop-Diktier-App mit lokalen und Cloud-Spracherkennungs-Engines, Notizen, Meeting-Aufnahme, Anbindungen, einem Assistenten und optionalem Herstellerkonto in der Cloud |
| Art | Electron-Desktopanwendung (Node-Hauptprozess, Web-Oberfläche) mit automatischem Updater |
| Upstream | `OpenWhispr/openwhispr` - Lizenz MIT |
| Geprüfte Version | Tag `v1.11.0` = `b9e9ebefac4b961456c269164a93ddfdd53438b9` |
| Geprüft am | 31.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (nur Claude-Audit; Codex-Audit ausstehend) |
| Empfehlung | nur mit Auflagen einsetzen |

## Einschätzung

OpenWhispr ist eine große, schnell veränderliche Anwendung mit vielen Funktionen. Das Diktieren kann lokal
oder gegen einen vom Nutzer gewählten kompatiblen Endpunkt ohne Konto laufen, doch die Voreinstellungen
zeigen auf die Hersteller-Cloud und müssen bewusst geändert werden. Das Fenster für Einstellungen und
Assistent läuft mit abgeschwächter Isolation, minimaler Inhaltsrichtlinie und sehr vielen internen
Aufrufen mit wenigen Absenderprüfungen, was jede Skript-Einschleusung schwerwiegend machen würde. Es
wurden keine Telemetriedienste gefunden, und Upstream hat einige frühere Probleme behoben, doch Vorschläge
zur Härtung der Fensterisolation wurden nicht übernommen. Die Update-Prüfung lässt sich nicht abschalten,
und es gibt keinen zentralen Offline-Schalter. Insgesamt ist das Risiko für ein Diktierwerkzeug mittel bis hoch.

## Hauptrisiken

- Schwache Isolation der Oberfläche (Sandbox und Websicherheit aus, minimale Inhaltsrichtlinie, viele ungeschützte interne Aufrufe).
- Ein Handler für Anmelde-Links, der eine Sitzung ohne Statusprüfung annimmt und Anmelde-Fälschung ermöglicht.
- Fehlende Härtungsschalter der Programmdatei und weitreichende macOS-Berechtigungen.
- Update-Prüfungen und Herstellerverbindungen, die auch mit eigenem Endpunkt bestehen bleiben; kein zentraler Offline-Schalter.
- Eine lokale Steuerbrücke und mehrere lokale Hilfsserver ohne Authentifizierung.
- Downloads ohne Hash-Fixierung, standardmäßig dauerhaft gespeicherter Klartext-Verlauf und Agenten-Werkzeuge, die ohne Freigabe handeln.

## Empfehlung

Geeignet nur für Einzelplatzrechner und für Leser, die eine große Angriffsfläche akzeptieren. Installer
und Signatur vor der Nutzung prüfen, sich nicht anmelden, alle Modi auf den eigenen Endpunkt umstellen
und Meeting-Aufnahme, Anbindungen, Assistent und Cloud-Abgleich abschalten. Nur die nötigen Netzwerkziele
erlauben, die Verlaufsdauer auf das Minimum setzen und nur Mikrofon- und Bedienungshilfen-Rechte vergeben.
Sind die Befunde zur Fensterisolation nicht tragbar, ist ein kleineres, rein lokales Diktierwerkzeug vorzuziehen.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
