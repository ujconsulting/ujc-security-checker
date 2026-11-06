<!-- source: README.md sha256:f34a825c0efa9e6bf691358fee5b5c796f18774e0d992484216fd10211f7e6be -->
[English](README.md) | [Deutsch](README_de.md)

# Meldungen des ujc-security-checker selbst - Register

Erzeugt aus [`register.json`](register.json) mit `python tools/disclosures/register.py readme` - nicht von Hand bearbeiten. Die Einträge stehen in der Sprache des Registers (Englisch).
Ablauf und Regeln: Skill [`finding-disclosure`](../.claude/skills/finding-disclosure/README_de.md); Beobachtung: `python tools/disclosures/disclosure_watch.py`, Berichte bleiben lokal unter `private/`.

Bedeutung des Status: `fix-pr` = ein PR/Commit bezieht sich darauf (eine Behauptung, nicht geprüft); `fixed` setzt nur ein Mensch nach Lesen des gemergten Codes; `closed` = upstream geschlossen, Grund siehe Notiz.

| ID | Repo | Befund | Schwereklasse | Kanal | Referenz | Gemeldet | Status | Zuletzt geprüft |
|---|---|---|---|---|---|---|---|---|

## Begründung der Schwereklasse und Notizen


Meldungen zu geprüften Repositories bleiben lokal bei der jeweiligen Akte (nicht versioniert): `private/records/<name>/disclosures/REGISTER.md`.
