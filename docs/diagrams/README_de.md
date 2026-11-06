<!-- source: README.md sha256:df65e78824e40083676122549495f66861f55aff11fdf073128c47f9906c94fd -->
[English](README.md) | [Deutsch](README_de.md)

# Ablaufdiagramme

Die Diagramme in der README und im Einstieg sind feste SVG-Bilder. Sie erscheinen sofort und hängen nicht vom Live-Mermaid-Viewer von GitHub ab.

- `<name>.mmd`: die Mermaid-Quelle. Geändert wird diese Datei, nie das Bild.
- `<name>.svg`: das erzeugte Bild. Seine erste Zeile nennt die Quelle und ihren Hash.
- `<name>_de.mmd`, `<name>_de.svg`: die deutsche Fassung, wo der Einstieg eine hat. Die README nutzt in beiden Sprachen die englischen Diagramme.
- `mermaid-config.json`: die Einstellungen zum Erzeugen. Beschriftungen müssen SVG-Text sein (`htmlLabels: false`), weil GitHub diese Dateien über ein Bild-Tag anzeigt, das HTML-Beschriftungen nicht darstellt.

## Nach einer Änderung an einer Quelle

1. Die `.mmd` mit Mermaid und `mermaid-config.json` zur `.svg` rendern. Diese Bilder entstanden mit Mermaid 12.3.0 im Browser.
2. Dem Bild eine feste Größe aus seiner `viewBox` geben (`width`, `height`) und einen weißen Hintergrund, damit es auch auf dunklen Seiten lesbar bleibt.
3. `<!-- source: <name>.mmd sha256: -->` als erste Zeile behalten und `python tools/public_check.py --stamp docs/diagrams/<name>.svg` ausführen.

`tools/public_check.py` weist ein Bild ohne diese Zeile ab, ein Bild, dessen Quelle sich geändert hat, und eine Quelle ohne Bild.
