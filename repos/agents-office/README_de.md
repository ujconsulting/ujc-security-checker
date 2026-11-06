<!-- source: README.md sha256:a721f5c5049ea3a908c280b8fa80c85bfb18404b885b0a800ffa8ca6ac887b94 -->
[English](README.md) | [Deutsch](README_de.md)

# agents-office - Kurzfassung der Prüfung

| | |
|---|---|
| Was | Lokale Webanwendung, in der viele KI-Agenten mit den angebundenen Diensten des Nutzers Aufgaben, Chats und zeitgesteuerte Routinen bearbeiten |
| Art | Node.js-Anwendung, Installation aus einem Git-Repository (kein veröffentlichtes Paket) |
| Upstream | `ajsahni/agents-office` - Lizenz PolyForm Noncommercial 1.0.0 plus Zusatzbedingungen |
| Geprüfte Version | Tag `v3.2.1-beta.2` = `f8be2666d062903ff53bb72fad0db31740d020a2` |
| Geprüft am | 12.10.2026 |
| Urteil | `DO NOT USE` (Erstaudit durch Claude; kein zweiter Prüfer) |
| Empfehlung | in der ausgelieferten Form nicht einsetzen |

## Bewertung
Agents Office bietet eine bequeme lokale Oberfläche, um ein Team von Agenten mit zeitgesteuerten Routinen zu betreiben.
Die geprüfte Version gibt diesen Agenten sehr weitreichenden Zugriff: Sie erben alle angebundenen Dienste des Nutzers,
können ohne Anwesenheit des Nutzers handeln, und gespeicherte Ergebnisse fließen in spätere Prompts zurück. Der Schutz
gegen Missbrauch durch nicht vertrauenswürdige Inhalte oder andere lokale Prozesse ist dünn. Das Projekt ist eine Beta,
und die Lizenz schränkt die kommerzielle Nutzung ein. Auf jedem Rechner mit echten Mail-, Kalender- oder
Browser-Sitzungen sind die Risiken ernst.

## Hauptrisiken
- Agenten erhalten Zugriff auf alle angebundenen Dienste und standardmäßig auf den angemeldeten Browser des Nutzers.
- Zeitgesteuerte Routinen handeln selbstständig, sodass manipulierte Eingaben unbeaufsichtigt Aktionen auslösen können.
- Gespeicherte Ergebnisse und gelernte Regeln werden als Prompt-Eingabe wiederverwendet, was dauerhafte Manipulation ermöglicht.
- Die lokale Oberfläche ist nur begrenzt gegen andere Prozesse oder Webseiten auf demselben Rechner geschützt.
- Ein gespeichertes Anmelde-Token wird für eine Nutzungsanzeige gelesen und an einen nicht öffentlich dokumentierten Endpunkt des Herstellers gesendet.
- Die Lizenz ist nicht-kommerziell und hat Zusatzbedingungen, was den Einsatz in Unternehmen einschränkt.

## Empfehlung
Die geprüfte Version nicht auf einem Rechner mit echten Konten einsetzen. Wer sie dennoch erproben will, tut das nur in
einer wegwerfbaren, isolierten Umgebung ohne echte Zugangsdaten und mit abgeschalteter Browser-Anbindung und
abgeschalteten unbeaufsichtigten Routinen. Eine spätere Upstream-Version kann das Bild ändern und bräuchte eine eigene Prüfung.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
