<!-- source: README.md sha256:648d2583571398c63f333ec6b281e7a2fef264d4aafb543d7b784d908c77ba6c -->
[English](README.md) | [Deutsch](README_de.md)

# rustdesk-server - review summary

| | |
|---|---|
| Was | Selbst betreibbarer Vermittlungs- (ID-) Server und Relay für RustDesk-Clients, quelloffene Ausgabe |
| Art | Rust-Netzwerkdienste, ausgeliefert als Pakete und Container-Image |
| Upstream | `rustdesk/rustdesk-server` - Lizenz AGPL-3.0 |
| Geprüfte Version | Tag `1.1.16` = `73523b31cfd25d77dee862e6fc9f5e1fb5e485ef` |
| Geprüft am | 31.10.2026 |
| Urteil | `USABLE WITH CONDITIONS` (Claude-Audit; Codex-Audit ausstehend) |
| Empfehlung | nur mit Auflagen einsetzen |

## Einschätzung

Der Server ist klein und leitet keinen beliebigen Verkehr weiter, was einige Missbrauchswege begrenzt.
Die Ende-zu-Ende-Verschlüsselung übernehmen die Clients, aber der ID-Server signiert die Schlüssel und
ist damit die Vertrauensbasis. Die geprüfte Version hat mehrere Schwächen, die systembedingt aus dem
Internet erreichbar sind: nur teilweise behobenes Reflexions- und Verstärkungsverhalten über UDP, eine
Schlüsseloption, die weniger schützt, als sie vermuten lässt, und eine veraltete Parser-Bibliothek im
Netzwerkpfad. Die mitgelieferten Voreinstellungen laufen mit vollen Rechten und ohne Härtung. Korrekturen
liegen im Entwicklungszweig, waren aber nicht Teil des Releases. Das Risiko ist mittel bis hoch, wenn der
Server ohne zusätzliche Maßnahmen erreichbar ist.

## Hauptrisiken

- Paketverarbeitung, die sich für Reflexions- und Verstärkungsangriffe gegen Dritte missbrauchen lässt.
- Eine Schlüsseloption, die nur bei einigen Anfragearten geprüft wird, sodass die meisten Protokollpfade auch ohne sie funktionieren.
- Eine Parser-Abhängigkeit mit bekanntem Sicherheitshinweis steht vor jeder Schlüsselprüfung; ein Absturz aus der Ferne ist plausibel, wurde aber nicht verifiziert.
- Ungehärtete Standard-Dienstkonfiguration: volle Rechte, lax geschützte Schlüsseldatei, offenes Relay ohne Schlüssel.
- Keine wirksame Begrenzung der Paketgröße oder der Verbindungen vor der Anmeldung; die vorhandenen Registrierungsgrenzen genügen gegen Ressourcenerschöpfung nicht.
- Ein täglicher ausgehender Aufruf beim Hersteller mit stabiler Geräte-Kennung sowie langfristige Speicherung von Client-Adressen.

## Empfehlung

Nur einsetzen, wenn aus dem geprüften Quelltext mit aktualisierten Abhängigkeiten gebaut wird (oder die
Upstream-Korrekturen eingespielt werden), das Schlüsselpaar vorab erzeugt und geschützt wird, die Dienste
als unprivilegierter, gehärteter Dienst laufen und die Firewall auf die nötigen Ports mit Ratenbegrenzung
und Filterung ausgehender Verbindungen beschränkt ist. Starke, eindeutige Passwörter auf jedem Zielrechner
bleiben die eigentliche Sicherheitsgrenze. Ein Neubau der Abhängigkeiten und allgemeine Ratenbegrenzungen
allein genügen nicht: den Schlüssel auf beiden Diensten erzwingen, die nicht benötigten Web-Socket-Dienste sperren,
ausgehende Filterung gegen Reflexion ergänzen und keinen lokalen Reverse-Proxy davorsetzen. Die unveränderten Release-Pakete nicht direkt ins Internet stellen.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
