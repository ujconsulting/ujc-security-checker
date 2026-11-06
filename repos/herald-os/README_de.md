<!-- source: README.md sha256:7a6eb2e4135edb57f45454b7e8b07a18ae7adff7aebe2a64921c42ebf5c63ef9 -->
[English](README.md) | [Deutsch](README_de.md)

# herald-os - Kurzfassung der Prüfung

| | |
|---|---|
| Was | Desktop-Shell und Linux-Image um einen lokalen KI-Agenten, mit einem Plugin, das dem Agenten Steuerung von Apps, Dateien und Bildschirm erlaubt |
| Art | Electron-Desktop-App, Linux-Image und Installer, Python-Agenten-Plugin |
| Upstream | `iamlukethedev/Herald-OS` - Lizenz MIT |
| Geprüfte Version | Tag `v0.1.0-alpha.3` = `1b3508555224a3040681a64199fe848e5c74349b` |
| Geprüft am | 12.10.2026 |
| Urteil | `DO NOT USE` (Erstaudit durch Claude, für den Einsatz als Zusatz zu einem bestehenden Headless-Agenten; kein Codex-Audit) |
| Empfehlung | nicht einsetzen; allenfalls in einer Wegwerf-VM erproben |

## Bewertung
Herald OS ist eine frühe Alpha eines einzelnen Maintainers mit sehr hoher Commit-Rate und einem jungen Repository. Es
hat durchdachte Schutzansätze wie Berechtigungsstufen, eine Richtliniendatei und ein Audit-Protokoll für die
Werkzeuge zur Maschinensteuerung (sie sind Komfortkontrollen, keine Sicherheitsgrenze, und das Audit-Protokoll ist
nicht manipulationssicher), und das Upstream-Projekt hat private Schwachstellenmeldungen aktiviert. Release-
Artefakte werden aber nur mit Prüfsummen statt Signaturen ausgeliefert und wurden nicht gegen den getaggten Quellcode
verglichen. Die Prüfung hielt es für das Szenario, es zu einer bestehenden Headless-Agenten-Installation
hinzuzufügen, für ungeeignet. Der Scanner-Lauf fand keine Geheimnisse und einige transitive Abhängigkeitshinweise.

## Hauptrisiken
- Das Agenten-Plugin kann Anwendungen, Dateien und Bildschirm steuern, ein manipulierter Agent hat daher große Reichweite.
- Das Linux-Image legt ein privilegiertes Konto ohne Passwort an, mit automatischer Anmeldung und großzügigen Voreinstellungen der Sicherheitsrichtlinie.
- Release-Images und Installer sind nicht signiert, was die Prüfung des Installierten einschränkt.
- Installationsschritte hängen von nachgeladenen Komponenten ab, die nicht strikt festgelegt sind.
- Das Projekt ist Alpha, wird von einer Person gepflegt und ändert sich sehr schnell.
- Einige Abhängigkeiten tragen bekannte Sicherheitshinweise.
- Die Plattformunterstützung ist unvollständig, das Verhalten auf manchen Systemen ist ungetestet.

## Empfehlung
Nicht auf einem Rechner mit echten Daten oder Konten einsetzen. Wer es ausprobieren will, tut das nur in einer
wegwerfbaren virtuellen Maschine in einem eigenen Netzsegment, mit sofort gesetztem Passwort und ohne echte Zugangsdaten, baut aus dem Quellcode statt Release-Artefakten zu
vertrauen und wartet auf eine reifere, signierte Version, bevor es breiter eingesetzt wird.

---
*Statische Prüfung der oben genannten Version; keine Gewähr, spätere Versionen können abweichen. Vorgehen: siehe [Projekt-README](../../README_de.md).*
