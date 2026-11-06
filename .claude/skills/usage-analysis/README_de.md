<!-- source: README.md sha256:68813be42b169806e142210d98fc8abd941001e706ba319fab26dfd18a8cd519 -->
[English](README.md) | [Deutsch](README_de.md)

# usage-analysis

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Beantwortet „wo in meinen Projekten hilft dieses Werkzeug und wo nicht?“, bevor der Auftraggeber
darüber entscheidet. Die Analyse legt den Einsatzumfang fest, gegen den das Bedrohungsmodell
geschrieben wird (Schritt 8 von `tool-review`). Sie nennt die eigenen Projekte des Auftraggebers
und ist deshalb **privat**: `private/repos/<name>/usage-analysis.md`. Die öffentliche Zusammenfassung
sagt nichts zum eigenen Einsatz.

## Wann

- Schritt 7 von `tool-review` ist erreicht;
- jemand fragt, ob sich ein Werkzeug lohnt oder wo es hilft;
- nach einer neuen Runde oder einem Upstream-Update muss die Analyse nachgezogen werden;
- jemand fragt, wie selbständig ein Agent mit dem Werkzeug arbeiten kann.

## Ablauf

1. Das private Portfolio lesen (`private/context/portfolio.md`, falls vorhanden) und bei Bedarf
   die `CLAUDE.md` von Kandidatenprojekten - nur lesend, keine Kundenordner, keine Secrets.
2. Das Werkzeug in eigenen Worten beschreiben, einschließlich der Grenzen des geprüften Stands.
3. Einsatzmatrix je Projekt: Anwendungsfall, messbarer Nutzen, Aufwand, Datenklasse (verlassen
   Inhalte den Rechner?), Empfehlung (nutzen / Pilot / nein).
4. Ausschlussbereiche, Überschneidungen mit vorhandenen Werkzeugen, Empfehlung mit Pilot und
   Abbruchkriterium.
5. Pflichtabschnitt 6 „Autonomes agentisches Arbeiten“: Beitrag je Phase, Schleifenschluss,
   Sandbox-Modell, GUI-Automatisierung, Risiken, Bewertung hoch/mittel/niedrig - getrennt für den
   Entwicklerrechner (E) und eine isolierte Autonomie-Umgebung (A).

## Befehle

Keine eigenen. Vorlage: `private/templates/usage-analysis.md`; Ergebnis:
`private/repos/<name>/usage-analysis.md`; die öffentliche Zusammenfassung `repos/<name>/README.md` wird nicht damit ergänzt.

## Beispiel

Für ein Code-Graph-Werkzeug zeigt die Matrix einen klaren Nutzen in zwei großen Codebasen
(Abhängigkeiten vor der Änderung einer Datenbank-View, Schätzung: 20 Minuten je Änderung), keinen
Einsatz für Kundendaten (Cloud-Backend), Überschneidung mit einer vorhandenen Wissensbasis.
Empfehlung: Pilot in einem Projekt für vier Wochen, Abbruch bei weniger als fünf Treffern pro Woche.

## Siehe auch

[`tool-review`](../tool-review/README_de.md), [`docs/SKILLS_de.md`](../../../docs/SKILLS_de.md).
