[English](README.md) | [Deutsch](README_de.md)

# Flow diagrams

The diagrams in the README and the getting-started guide are fixed SVG images, so they appear at once and do not depend on GitHub's live Mermaid viewer.

- `<name>.mmd`: the Mermaid source. Change this file, never the image.
- `<name>.svg`: the rendered image. Its first line names the source and its hash.
- `<name>_de.mmd`, `<name>_de.svg`: the German version where the guide has one. The README uses the English diagrams in both languages.
- `mermaid-config.json`: the render settings. Labels must be SVG text (`htmlLabels: false`), because GitHub shows these files through an image tag, which does not display HTML labels.

## After changing a source

1. Render the `.mmd` with Mermaid and `mermaid-config.json` to the `.svg`. These images were made with Mermaid 12.3.0 in a browser.
2. Give the image a fixed size from its `viewBox` (`width`, `height`) and a white background, so it stays readable on a dark page.
3. Keep `<!-- source: <name>.mmd sha256: -->` as the first line and run `python tools/public_check.py --stamp docs/diagrams/<name>.svg`.

`tools/public_check.py` refuses an image without this line, an image whose source changed, and a source without an image.
