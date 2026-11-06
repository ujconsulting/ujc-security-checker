<!-- source: README.md sha256:46db07dc8ad2df563c7a9003a5b1d479a88f08bd4602625785f68885d6a784c5 -->
[English](README.md) | [Deutsch](README_de.md)

# handy - review summary

| | |
|---|---|
| Was | Desktop-App für Sprache-zu-Text per Tastenkombination mit lokalen Modellen; der Text wird in die aktive Anwendung eingefügt |
| Art | Tauri-2-Desktopanwendung (Rust-Backend, Web-Oberfläche) |
| Upstream | `cjpais/Handy` - Lizenz MIT |
| Geprüfte Version | Tag `v0.9.8` = `14f6f0d31cb22a4268acfbddba3052820fd0a06e` |
| Geprüft am | 31.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (Claude- und Codex-Audit, gleiches Urteil) |
| Empfehlung | nur mit Auflagen einsetzen |

## Einschätzung

Die App ist klein, transkribiert lokal, hat keine Serverkomponente und keinen lauschenden Port, und es
wurde keine Telemetrie gefunden. Netzwerkverkehr beschränkt sich auf Modell-Downloads, eine signierte
Update-Prüfung und einen optionalen, vom Nutzer eingerichteten Sprachmodell-Anbieter, der standardmäßig
aus ist. Die Befunde sind überwiegend Fälle von Verteidigung in der Tiefe und keine unmittelbar
ausnutzbaren Fehler. Am auffälligsten sind die Integritätsprüfung bei Modell-Downloads, eine sehr
großzügige Web-View-Konfiguration und die lokale Speicherung jedes Diktats. Ein Prüfer stufte zwei
Befunde höher ein als der andere. Insgesamt ist das Risiko gering bis mittel.

## Hauptrisiken

- Heruntergeladene Modelldateien werden nicht immer gegen eine veröffentlichte Prüfsumme verifiziert; native Parser lesen sie anschließend.
- Die Web-View läuft mit großzügiger Inhaltsrichtlinie und weitem Dateizugriff, was eine künftige Skript-Einschleusung verstärken würde.
- Jedes Diktat wird als Audio und Text gespeichert, und die Aufbewahrung lässt sich auf unbegrenzt stellen.
- Schlüssel für den optionalen Sprachmodell-Anbieter liegen im Klartext in den Einstellungen.
- Die Ausgabe dieses Anbieters wird ungefiltert eingefügt und könnte bei aktiviertem Auto-Absenden eine Aktion auslösen.
- Die Build-Pipeline nutzt per Tag fixierte Actions und einige ungeprüfte Downloads; Abhängigkeits-Meldungen bestehen, scheinen unter macOS aber überwiegend nicht erreichbar.

## Empfehlung

Vertretbar auf Einzelplatzrechnern mit Festplattenverschlüsselung. Die optionale Sprachmodell-Verarbeitung
aus oder lokal lassen, Auto-Absenden und externe Einfüge-Skripte abschalten, die Verlaufsdauer auf das
Minimum setzen, gespeicherte Aufnahmen bei Weitergabe des Rechners löschen und nur Mikrofon- und
Bedienungshilfen-Rechte vergeben. Updates von Hand nach Prüfung des jeweiligen Downloads einspielen und
Modelle einmalig bewusst laden.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
