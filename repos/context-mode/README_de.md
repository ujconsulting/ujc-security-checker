<!-- source: README.md sha256:ea6192f2caf26ca1ecb4d70c2835eaeaaddb203af3c356c984851713a8d0976a -->
[English](README.md) | [Deutsch](README_de.md)

# context-mode - Kurzfassung der Prüfung

| | |
|---|---|
| Was | MCP-Server mit Hooks, der große Werkzeugausgaben aus dem Kontext eines Agenten heraushält und den Sitzungszustand nach einer Verdichtung wiederherstellt |
| Art | Claude-Code-Plugin (auch für andere Agenten-CLIs) und npm-Paket |
| Upstream | `mksglu/context-mode` - Lizenz Elastic-2.0 (quelloffen, aber keine Open-Source-Lizenz) |
| Geprüfte Version | Tag `v1.0.169` = `589d8214d56740a28b5f7bf63167743d586b0b40` |
| Geprüft am | 21.10.2026 |
| Urteil | `DO NOT USE` (Erstaudits von Claude und Codex stimmen überein) |
| Empfehlung | in der ausgelieferten Form nicht einsetzen |

## Bewertung
Die Idee ist stimmig und löst ein echtes Problem: Lange Werkzeugausgaben verschwenden Kontext, und ein lokaler Index mit
Suche kann helfen. Die Umsetzung hängt sich jedoch an nahezu jeden Werkzeugaufruf, zeichnet Aufrufe und Prompts in einer
lokalen Datenbank auf, installiert Abhängigkeiten zur Laufzeit und kann sich aus dem Standard-Branch seines
Repositorys selbst aktualisieren. Die eingecheckten Bundles waren gegenüber dem Quellcode veraltet, und die
Marketplace-Installation folgt einem beweglichen Branch, sodass das Ausgeführte nicht an einen geprüften Stand
gebunden ist. Upstream hatte damals keinen Meldekanal für Sicherheitsthemen. Die Lizenz ist keine Open-Source-Lizenz.

## Hauptrisiken
- Hooks auf fast alle Werkzeug-Ereignisse geben dem Plugin Einblick in und Einfluss auf alles, was der Agent tut.
- Sitzungsaufzeichnungen können sensible Prompts und Befehlsausgaben in einer lokalen Datenbank halten.
- Nachinstallation von Abhängigkeiten zur Laufzeit und Selbstaktualisierung von einem beweglichen Branch schwächen die Lieferkettenkontrolle.
- Die Werkzeuge zur Codeausführung laufen außerhalb der Befehlswächter des Hosts und ohne Isolation: Unterprozesse behalten das echte Home-Verzeichnis, die Zugangsdaten sowie vollen Netzwerk- und Dateizugriff.
- Es verändert bei jedem Start die globale Agenten-Konfiguration des Nutzers, repariert und aktiviert sich selbst wieder und hinterlässt nach der Deinstallation einen Hook.
- Für Sicherheitsbefunde gibt es keinen Meldekanal, und der Abhängigkeitsbestand hatte bekannte Lücken.

## Empfehlung
Die geprüfte Version nicht einsetzen. Wird die Idee der Kontextersparnis gebraucht, ist ein Ansatz vorzuziehen, der die
installierte Version festschreibt, Selbstaktualisierung und Laufzeitinstallation abschaltet und Hooks auf die Werkzeuge
beschränkt, die er sehen muss. Ein anderer Upstream-Stand bräuchte eine eigene Prüfung.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
