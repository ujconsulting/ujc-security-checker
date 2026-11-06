<!-- source: README.md sha256:e7744e3175c3615f05ed8005766e1ba08b71be1a47030d4250904d84a05551a8 -->
[English](README.md) | [Deutsch](README_de.md)

# mirofish - review summary

| | |
|---|---|
| Was | Prognosewerkzeug nach dem Prinzip "Schwarmintelligenz": baut aus hochgeladenen Dokumenten einen Wissensgraphen, simuliert Agenten-Diskussionen mit Sprachmodellen und schreibt einen Prognosebericht |
| Art | Webanwendung (Python-Backend, Vue-Oberfläche), ausgeliefert als Container-Image |
| Upstream | `666ghj/MiroFish` - Lizenz AGPL-3.0 |
| Geprüfte Version | Tag `v0.1.2` = `985f89f49acbb44ee14d9d680682c741a44eeebe` |
| Geprüft am | 31.10.2026 |
| Urteil | `DO NOT USE` (Claude- und Codex-Audit, gleiches Urteil) |
| Empfehlung | nicht einsetzen |

## Einschätzung

MiroFish ist ein Prototyp im Forschungsstil und kein gehärteter Dienst; die Betreiber sagen selbst, es sei
nur für vertrauenswürdige lokale Nutzung gedacht. Die geprüfte Version stellt ihre gesamte Schnittstelle
ohne jede Authentifizierung bereit, erlaubt Anfragen von jedem Ursprung, wird mit aktiven Debug-Funktionen
ausgeliefert und gibt interne Fehlerdetails an Aufrufer zurück. Mehrere Anfrageparameter fließen ohne
Prüfung in Dateipfade ein, was Zugriff auf und Löschen von Daten außerhalb des vorgesehenen Bereichs
erlaubt. Zudem wird jedes hochgeladene Dokument an einen verpflichtenden Cloud-Dienst eines Dritten
gesendet, ohne Möglichkeit zum Selbstbetrieb. Die meisten Befunde wurden von den Betreibern als offen
bestätigt, einige sind Absicht. Das Risiko ist hoch.

## Hauptrisiken

- Keine Authentifizierung oder Autorisierung auf irgendeiner Route, dazu offener Zugriff von jedem Ursprung und ein Debug-Modus.
- Ungeprüfte Kennungen in Dateioperationen, die unbeabsichtigtes Lesen, Schreiben und Löschen erlauben.
- Ausführliche interne Fehlerausgaben an Clients.
- Verpflichtende Übertragung aller hochgeladenen Dokumente an einen Cloud-Dienst eines Dritten; Löschen wirkt dort nicht.
- Container-Image läuft als Administrator mit Entwicklungsserver und veränderlichen Tags.
- Gespeicherte Skript-Einschleusung durch unmaskierte Modellausgabe sowie Abhängigkeiten mit vielen bekannten Meldungen.

## Empfehlung

Diese Version nicht einsetzen: Sie ist nicht für Umgebungen gebaut, in denen Unbefugte sie erreichen
können, und der Umgang mit Dokumenten ist mit vertraulichen oder personenbezogenen Daten unvereinbar.
Wer dennoch experimentiert, sollte das auf einem isolierten Rechner tun, hinter einem authentifizierenden
Proxy, ohne veröffentlichte Ports, mit abgeschaltetem Debug-Modus, eingeschränktem ausgehendem Verkehr
und nur mit unkritischen Dokumenten.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
