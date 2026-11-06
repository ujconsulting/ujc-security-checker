<!-- source: README.md sha256:4b6fff290989f72f9b90b5a999d7282d9dbb0177e1268c4f9192b1065d7739e9 -->
[English](README.md) | [Deutsch](README_de.md)

# docker-sandbox

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Regeln und Standardmuster für Wegwerf-Container in Docker, die fremden Code installieren, testen
oder ausführen: Containertests, Neubau von Bundles, Probeläufe von CLIs oder MCP-Servern und die
Verhaltensprobe. Ein Containerlauf führt Paketcode aus und findet deshalb **nur nach
ausdrücklicher Freigabe** für genau dieses Werkzeug und diese Revision statt.

## Wann

- Schritt 11 (Containertests) oder 11b (Verhaltensprobe) von `tool-review` steht an;
- ein fremdes Paket oder ein MCP-Server soll ausprobiert werden;
- ein Containertest-Skript wird geschrieben oder geändert;
- es ist zu entscheiden, ob Docker reicht oder ein LXC oder eine Windows-VM nötig ist.

## Ablauf

1. Freigabe liegt vor; Stand von Fork oder Klon ist committet.
2. `tools/setup.sh --check` -> Exit 0.
3. Skript starten (lange Läufe im Hintergrund); es prüft den Egress, hält den Image-Digest fest und
   läuft abgekoppelt.
4. `network.txt` muss `network_disconnected` enthalten, sonst zählt der Lauf nicht.
5. `egress.log` / `egress.log.blocked` lesen - jeder geblockte Versuch ist ein Befund.
6. Gegen einen Upstream-Vergleichslauf auswerten; Ergebnis als Runde in `private/records/<name>/reviews/`.

Die verpflichtende Netzregel: nie das Standard-Bridge-Netz oder `--network host`; Installation nur
in `ujc-sandbox-net` über `ujc-sandbox-proxy:3128` nach der Egress-Prüfung, danach das Netz
vollständig trennen und die Trennung prüfen. Außerdem: Quelltext per `git archive` kopiert (kein
Mount des Arbeits-Repositorys), Arbeitsverzeichnis außerhalb jedes Repositorys,
`--cap-drop ALL`, `no-new-privileges`, Ressourcengrenzen, kein Docker-Socket, keine Ports, keine
Secrets, Images per Digest.

## Befehle

```bash
UJC_FOCUS_TESTS="tests/test_ujc_*.py" tools/container_test_python.sh <fork> HEAD <upstream-tag> <extras>
UJC_NPM_BUILD=1 UJC_BUNDLE_DIRS="dist" tools/container_test_npm.sh <fork> HEAD <upstream-tag>
UJC_PROBE_APPROVAL=<commit-sha> tools/behavior_probe.sh quarantine/<name> <ref> '<einstiegspunkt>'
docker ps -a --filter label=ujc.sandbox=1     # danach darf nur noch der Proxy erscheinen
```

## Beispiel

Ein npm-Fork mit von Hand gepatchten Bundles: nach Freigabe installiert
`UJC_NPM_BUILD=1 tools/container_test_npm.sh` über den Proxy, trennt das Netz, führt die Tests aus
und baut die Bundles ohne Netz neu; `bundle-diff-summary.txt` zeigt nur Formatierungsunterschiede,
Handpatches und Quelltext stimmen also überein.

## Siehe auch

[`tools/README_de.md`](../../../tools/README_de.md), [`tools/egress/README_de.md`](../../../tools/egress/README_de.md),
[`sandbox-setup`](../sandbox-setup/README_de.md), [`proxmox-lxc-sandbox`](../proxmox-lxc-sandbox/README_de.md).
