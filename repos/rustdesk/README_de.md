<!-- source: README.md sha256:5a32321b00223d4b8a6c079a5a855b70e96b1fb6ab6f7e9116dff89a24c42b14 -->
[English](README.md) | [Deutsch](README_de.md)

# rustdesk - review summary

| | |
|---|---|
| Was | Quelloffener Fernwartungs-Client und -Host (Bildschirm, Tastatur, Zwischenablage, Dateiübertragung, Terminal, Tunnel) |
| Art | Desktop- und Mobilanwendung, läuft nach der Installation als Systemdienst |
| Upstream | `rustdesk/rustdesk` - Lizenz AGPL-3.0 |
| Geprüfte Version | Tag `1.5.0` = `fada664df7a294d1d1a9ca3e7cd3637069122f17` |
| Geprüft am | 31.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (Claude-Audit; Codex-Audit ausstehend) |
| Empfehlung | nur mit Auflagen einsetzen |

## Einschätzung

RustDesk ist ein funktionsreiches Fernzugriffsprogramm mit Rust-Kern. Verbindungen zwischen den
Gegenstellen werden über einen Vermittlungsserver verschlüsselt und signiert, und die neueste Version
hat den Schlüsselaustausch verbessert. Die Schwächen liegen vor allem in optionalen Pfaden, Rückfallwegen
und Voreinstellungen: Ein Direktverbindungsmodus ist unverschlüsselt, mehrere Rückfälle senken die
Sicherheit unbemerkt ab, und standardmäßig erhält ein verbindender Partner fast alle Rechte. Das Projekt
hatte in diesem Jahr eine lange Reihe gemeldeter Schwachstellen, die außerhalb der üblichen
Advisory-Kanäle behandelt wurden; ein unabhängiges Audit wurde nicht gefunden. Insgesamt ist das Risiko
mittel und hängt stark von der Konfiguration ab. Die Prüfung war statisch und deckte nicht alle Dienste ab.

## Hauptrisiken

- Ein Direktverbindungsmodus ohne Verschlüsselung und ohne Host-Authentifizierung erlaubt die Übernahme durch einen Angreifer im selben Netz.
- Rückfälle auf Klartext oder auf einen ungeprüften Server-Schlüssel kann ein Nutzer durch Wegklicken eines Dialogs zulassen.
- Dauerpasswörter werden als schneller Hash gespeichert und nur durch schwache Begrenzungen gegen Durchprobieren geschützt.
- Großzügige Voreinstellungen (Dateiübertragung, Terminal, Tunnel, Zwischenablage) sowie optionaler Update- und Telemetrieverkehr.
- Der Vermittlungsserver ist die Vertrauensbasis; wer ihn kontrolliert, kann Sitzungen mitlesen.
- Das Werkzeug wird häufig für Betrug per Fernzugriff missbraucht, und gefälschte Download-Seiten existieren.

## Empfehlung

Vertretbar für Personen, die den Server selbst betreiben, den Server-Schlüssel auf jedem Client setzen,
pro Rechner lange, zufällige und eindeutige Passwörter nutzen und Direktzugriff per IP, LAN-Erkennung,
unnötige Rechte sowie automatische Updates abschalten. Nur aus der offiziellen Quelle installieren und
den Download prüfen. Keine Vorabversion einsetzen. Nicht auf Rechnern einsetzen, bei denen unbekannte
Dritte den Kontakt auslösen können.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
