<!-- source: README.md sha256:f09a8888174e901b6424e47b7991707ae9478e2accf64dac1eb1e94cc4288d39 -->
[English](README.md) | [Deutsch](README_de.md)

# linkedin-skills - review summary

| | |
|---|---|
| Was | Bündel aus 12 Agenten-Skills für LinkedIn-Inhalte (Schreiben, Kommentieren, Antworten, Planen, Auswertung) plus ein kleiner Python-Helfer, der über Scraping-Akteure liest und über eine Drittanbieter-API veröffentlicht |
| Art | Skill-Bündel / Plugin für Agenten mit Python-Hilfsbibliothek; keine Hooks, kein Server, keine Installation über Paketmanager |
| Upstream | `sergebulaev/linkedin-skills` - Lizenz MIT |
| Geprüfte Version | Tag `v1.1.28` = `8f8bc4b40a2d5419b2dcf898772b85712cfbdf41` |
| Geprüft am | 31.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (nur Claude-Audit; Codex-Audit noch nicht gelaufen) |
| Empfehlung | nur mit Auflagen einsetzen |

## Einschätzung

Die Skills sind überwiegend Anweisungen für den Agenten und erzeugen standardmäßig nur Entwürfe, die der
Nutzer von Hand einstellt. Der Code spielt erst eine Rolle, wenn Schlüssel zum Veröffentlichen oder Lesen
eingerichtet sind. In diesem Modus ist die Freigabe vor dem Veröffentlichen nur als Text formuliert und
nicht im Code erzwungen; ein getäuschter oder nachlässiger Agent könnte sofort veröffentlichen. Die
Abwehr nicht vertrauenswürdiger Inhalte besteht teils aus Text mit Lücken, und gespeicherte Profildaten
könnten eingeschleusten Text behalten. Telemetrie, automatische Updates, Hooks oder Änderungen an
Einstellungen wurden nicht gefunden, und die Netzwerkziele sind fest. Hinzu kommen Bedenken zu
Plattformbedingungen und Datenschutz beim Scraping und automatisierten Posten. Insgesamt ist das Risiko im
Entwurfsmodus gering und mit aktivierten Schlüsseln mittel.

## Hauptrisiken

- Die menschliche Freigabe vor dem Veröffentlichen wird vom Code nicht erzwungen, sobald Schlüssel gesetzt sind.
- Die Abwehr von Prompt-Injection bei Fremdinhalten ist unvollständig, und gespeicherte Profildaten können eingeschleusten Text dauerhaft behalten.
- Konfigurationsdateien werden in übergeordneten Verzeichnissen gesucht, und personenbezogene Daten landen im Plugin-Ordner.
- Scraping sowie Hinweise zu Menge und Automatisierung widersprechen den Plattformbedingungen und werfen Datenschutzfragen auf.
- Veröffentlichungsaufrufe können ohne Schutz vor Dubletten wiederholt werden.
- Nicht fixierte Installationswege, ein optionales externes Kommando als Backend und ein kommerzieller Empfehlungstrichter.

## Empfehlung

Unter diesen Bedingungen vertretbar für die Nutzung als Entwurfshilfe: eine feste Kopie der geprüften Version im Projektumfang
installieren, ganz ohne Schlüssel arbeiten und nur die Entwurfs-Skills nutzen. Wird das Veröffentlichen
aktiviert, nur einen einzelnen Veröffentlichungsschlüssel lokal ablegen, die Skriptausführung bei jedem Aufruf einzeln freigeben, nie über eine Allowlist, die Pfade für
Zeitplanung und eigenes Posten ungenutzt lassen (eine nur im Skill-Text niedergeschriebene Freigabe bindet den
Veröffentlichungscode nicht), auf Scraping-Funktionen und unbeaufsichtigte Sitzungen verzichten, personenbezogene Daten aus der
Versionsverwaltung heraushalten und jede Zahl in einem Entwurf selbst prüfen.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
