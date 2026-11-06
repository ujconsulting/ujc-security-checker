<!-- source: README.md sha256:06e289af9b2b55897d0675f614f84369b9d02267eaeb90a100d71b645b4a3a8f -->
[English](README.md) | [Deutsch](README_de.md)

# scanner-image — Scanner-Image `ujc-scanner:<YYYY-MM-DD>`

Ein Image mit allen Scannern und den Werkzeugen für die Verhaltensprobe. Es wird lokal gebaut, nicht aus
einer Registry gezogen, und enthält weder Tokens noch Geheimnisse.

## Bauen

```bash
tools/setup.sh              # builds when no image matches the current state of this folder
tools/setup.sh --rebuild    # forces a rebuild without cache
# by hand:
docker build --build-arg IMAGE_DATE=$(date +%F) -t ujc-scanner:$(date +%F) tools/scanner-image
```

`setup.sh` berechnet einen Hash über diesen Ordner (Dockerfile, Lock-Dateien, `scan_inside.sh`) und schreibt
ihn als Label `ujc.context` in das Image; daran erkennt es, ob ein Neubau nötig ist.
Der Build braucht Netzwerk (Standard-Build-Netzwerk von Docker) für die Downloads; alles Heruntergeladene
wird verifiziert (siehe unten). Das Image wird für `linux/amd64` gebaut, Größe rund 2,4 GB.

## Lieferkette

| Quelle | Verifikation |
|---|---|
| Basis `python:3.12-slim-bookworm` | per Digest fixiert (`ARG BASE`) |
| Binaries (gitleaks, trufflehog, osv-scanner, trivy, syft, grype, actionlint, hadolint, shellcheck, scorecard) | offizielle GitHub-Releases, SHA-256 im Dockerfile fixiert; beim Eintragen mit der Prüfsummendatei des Herstellers verglichen |
| gitleaks-Standardregeln (`config/gitleaks.toml` des Tags) | SHA-256 im Dockerfile fixiert |
| Node.js | offizielles Tarball von nodejs.org, SHA-256 aus `SHASUMS256.txt` |
| Semgrep-Regeln (`semgrep/semgrep-rules`) | fixierter Commit, Integrität über den Commit-Hash; Testfixtures entfernt |
| Python-Werkzeuge | jeweils in eigenem venv aus `lock/<name>.txt` (alle Abhängigkeiten mit Hash, `--require-hashes`, nur Wheels) |
| npm-Werkzeuge | `npm/package-lock.json` (Integritäts-Hashes), `npm ci --ignore-scripts` |
| Debian-Pakete (git, strace, tcpdump, inotify-tools, procps, ca-certificates) | feste Versionen aus bookworm |

**Lock-Dateien neu erzeugen:** `tools/scanner-image/generate_locks.sh` — läuft in Wegwerf-
Containern im internen Netzwerk über den Egress-Proxy (Liste `standard`), Python mit
`uv pip compile --no-build --generate-hashes` (kein Build-Backend fremder sdists), npm mit
`--package-lock-only --ignore-scripts`. Danach den Diff lesen, neu bauen, `VERSIONS.md` aktualisieren.

**Eine Version anheben:** Version **und** SHA-256 im Dockerfile ändern (die Prüfsummendatei des Herstellers
herunterladen, den Eintrag vergleichen) oder `lock/*.in` ändern und die Locks neu erzeugen. Bricht der Build,
weil Debian eine Paketversion ersetzt hat: die neue Version eintragen, nicht entpinnen.

## Werkzeuge und ihr Netzwerkverhalten

| Werkzeug | Zweck | lädt zur Laufzeit herunter? |
|---|---|---|
| gitleaks | Geheimnisse (Arbeitsbaum und Git-Historie) | nein |
| trufflehog | Geheimnisse | prüft auf Updates → `scan.sh` setzt `--no-update`; die Verifikation (`--no-verification` aus) würde Funde an die APIs der Anbieter senden |
| osv-scanner | Schwachstellen in Lockfiles | ja: OSV-API (`api.osv.dev`) — sendet Paketname und Version, keinen Code |
| trivy | Schwachstellen | ja: Datenbank von `mirror.gcr.io` (Rückfall `ghcr.io`); Telemetrie und Versionsprüfung per ENV aus |
| syft | SBOM | nein (Update-Prüfung per ENV aus) |
| grype | Schwachstellen auf der SBOM | ja: Datenbank von `grype.anchore.io`; Update-Prüfung per ENV aus |
| semgrep | SAST mit lokalen Regeln (`/opt/semgrep-rules`) | Metriken und Versionsprüfung per ENV aus; `--config p/...` (Registry) würde `semgrep.dev` brauchen — nicht vorgesehen |
| bandit, ruff, radon, lizard | Python-SAST, Lint, Komplexität | nein |
| guarddog | Heuristiken für bösartige Pakete | **ja**: lädt beim Start Listen beliebter Pakete (github.com, hugovk.github.io, packages.ecosyste.ms); ohne Netzwerk fällt es auf die mitgelieferten Listen zurück (nur Warnungen) |
| zizmor | Prüfung von GitHub Actions | offline (`ZIZMOR_OFFLINE`, `--offline`) |
| actionlint, hadolint, shellcheck | Workflows, Dockerfiles, Shell-Skripte | nein |
| jscpd | Duplikate | nein |
| knip | ungenutzter JS/TS-Code | nein, aber **lädt Projektkonfigurationen (`knip.ts`, `vite.config.ts` …) = führt Projektcode aus** → nicht in `scan.sh`, nur nach Freigabe wie eine Verhaltensprobe |
| scorecard | OpenSSF-Bewertung eines GitHub-Repositorys | braucht zur Laufzeit Netzwerk und `GITHUB_AUTH_TOKEN` (`-e GITHUB_AUTH_TOKEN`, Token nie im Image); nicht in `scan.sh` |
| snyk-agent-scan (Nachfolger von `mcp-scan`) | Agent-/MCP-/Skill-Komponenten | braucht `SNYK_TOKEN`, **sendet Komponentendaten an die Snyk-API** und startet MCP-Server zur Erkennung (= führt fremden Code aus) → nicht in `scan.sh`, nur nach Freigabe |
| strace, tcpdump, inotify-tools | Verhaltensprobe (`tools/behavior_probe.sh`) | nein |

MCP-/Agent-Scanner und Heuristiken (guarddog, snyk-agent-scan) haben eine hohe Falsch-Positiv-Rate:
sie sind Hinweise, kein Urteil — jeder Treffer wird gegen den Code verifiziert.

## Im Image

- Benutzer `scanner` (uid 10001), Arbeitsordner `/home/scanner`
- `/opt/ujc/scan_inside.sh` (der Ablauf von `tools/scan.sh` im Container), `/opt/ujc/gitleaks.toml`
- `/opt/semgrep-rules` (Commit in `UJC-COMMIT`), `/opt/ujc-apt-versions.txt`
- `/db` (Eigentümer `scanner`): Mountpunkt des Volumes `ujc-scanner-db` für die trivy/grype-DB

Versionen des aktuellen Builds: [`VERSIONS.md`](VERSIONS.md).
