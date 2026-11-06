<!-- source: README.md sha256:5a323c38e9b9355bab2a5bc9172754319cd52cbf02032657daa7abc1a6edfb00 -->
[English](README.md) | [Deutsch](README_de.md)

# tools — Verwendung

Alle Skripte sind einfache Kommandozeilenwerkzeuge (Bash; unter Windows Git Bash, unter Linux/macOS
bash ≥ 4) und setzen keinen bestimmten Agenten voraus. Die Ausgabe ist ausschließlich ASCII.

| Datei | Zweck | führt fremden Code aus? |
|---|---|---|
| `setup.sh` / `setup.ps1` | **ein Einstiegspunkt** für die gesamte Sandbox: Egress-Netzwerk, Proxy, Prüfung, Scanner-Image, Selbsttest; `--check`, `--rebuild`, `--remove` | nein |
| `egress/` | internes Netzwerk + Squid-Proxy mit Allowlist, `check.sh` (Doku: [`egress/README_de.md`](egress/README_de.md)) | nein |
| `scanner-image/` | Scanner-Image `ujc-scanner:<date>` mit allen Scannern (Doku: [`scanner-image/README_de.md`](scanner-image/README_de.md), Versionen: [`VERSIONS.md`](scanner-image/VERSIONS.md)) | nein |
| `quarantine_clone.py` | Quarantäne-Klon aus `owner/name`, `<alias>:owner/name` (andere Code-Hosts: [`disclosures/forge.py`](disclosures/README_de.md)), beliebiger Git-URL oder lokalem Pfad auf einem festen Commit unter `quarantine/<name>/` (Regel 2 der `CLAUDE.md` erzwungen; Nachweis `.claudex-tmp/<name>/clone.json`; `--self-test`) | nein (nur Git-Transport, nichts aus dem Repository wird ausgeführt) |
| `scan.sh` | alle statischen Scanner gegen einen Quarantäne-Klon | nein (nur lesend) |
| `cr_full_review.sh` | CodeRabbit-Vollreview einer kompletten Revision (leere Orphan-Basis) | nein — aber **Code geht an CodeRabbit**, kostet Kontingent |
| `container_test_python.sh` | Tests eines Python-Forks in einem isolierten Container, mit Vergleichslauf gegen Upstream | **ja** — nur nach Freigabe |
| `container_test_npm.sh` | Tests eines npm-Forks, optional Rebuild und Diff der Bundles gegen die Handpatches | **ja** — nur nach Freigabe |
| `behavior_probe.sh` | Einstiegspunkt eines Tools einmal unter strace/tcpdump/inotify ausführen | **ja** — nur nach Freigabe je Tool |
| `lib_sandbox.sh` | gemeinsame Bausteine (Egress-Voraussetzung, Digest, abgekoppelte Läufe, Netzwerktrennung, Proxy-Log) | — |
| `codex_skills_sync.py` | spiegelt `.claude/skills/` nach `.agents/skills/` für Codex (`--check`, `--self-test`); von git ignorierte Skills bleiben lokal und zählen in `--check` nicht mit | nein |
| `public_check.py` | Public/Private-Schranke vor jedem Commit und Push: interne Details, KI-Attribution, Deutsch außerhalb von `*_de.md`, Paarung README/`README_de.md` mit Quell-Hashes, Embargo; CR/BOM-Formatprüfung (CRLF erlaubt, wo `.gitattributes` es vorgibt); Modi: Arbeitsbaum, `--staged` (pre-commit), `--rev <commit>` (pre-push: die gepushten Commits, über git gelesen, samt deren eigener `.gitignore`-Regeln, nicht der Arbeitsbaum), `--history`, `--stamp`, `--self-test`; wird von `.githooks/pre-commit` und `pre-push` ausgeführt | nein |
| `codex_ro.py` | schreibgeschützter Codex-Wrapper aus dem claudex-loop-Plugin (Kopie, nicht von Hand ändern) | — |
| `ledger.py` | Ledger in `private/ledger/`: Entscheidung je Akte, Prüfläufe (`run codex` umschließt `codex_ro.py` und hält Modell, Effort, Zeiten und Thread-ID fest; `run backfill` liest die Runden-Dateien), Befund-Metadaten ohne Freitext (`check`, `salt`, `--self-test`) | nein |
| `export_dashboard.py` | Metadaten-Export für einen Dashboard-Ingest: Akten-Tabellen, Ledger, Register Feld für Feld; unveröffentlichte Meldungen und Befunde nur unter Platzhaltern; Formprüfung und Leak-Scan jedes Werts; standardmäßig Trockenlauf, `--send` sendet (`--cleartext`, `--self-test`) | nein |

## Setup (einmal je Rechner, danach bei Änderungen)

```bash
tools/setup.sh --check     # status, changes nothing (exit 0 = ready)
tools/setup.sh             # set up / complete (idempotent)
```

Windows PowerShell: `.\tools\setup.ps1 --check` (findet Git Bash, reicht durch). Ablauf,
Voraussetzungen, Fehlerbilder und Rückbau: Skill `sandbox-setup`.

Lokale Einstellungen (optional, von git ignoriert) in `private/`:

| Datei | Zeile | Wirkung |
|---|---|---|
| `private/egress.conf` | `UJC_EGRESS_LAN_TARGET=<ip>:<port>` | reales LAN-Ziel für den Negativtest von `check.sh` |
| `private/environment.conf` | `UJC_PROTECTED_PATHS=<path>;<path>` | die Skripte legen dort nie Arbeitsordner an (z. B. Projektordner unter Synchronisation) |
| `private/environment.conf` | `UJC_BASH=<path to bash.exe>` | Git Bash für `setup.ps1` |

## ⛔ Freigabe

`container_test_*.sh` und `behavior_probe.sh` **führen Paketcode aus** (Installation, Tests,
Build, Einstiegspunkt) — im Container, aber sie führen ihn aus. Nur nach ausdrücklicher Freigabe
durch den Eigentümer für genau diese Revision starten. Die Skripte setzen das durch: Die Freigabe ist
der vollständige Commit-SHA, auf den der Ref zeigt (`UJC_TEST_APPROVAL=<sha>` bzw.
`<fork-sha>+<upstream-sha>` mit Vergleichslauf, `UJC_PROBE_APPROVAL=<sha>`), und genau dieser
Commit wird archiviert - ein verschobener Tag oder Branch kann nicht nachrutschen. Eine
fehlgeschlagene oder abgebrochene Installation wird nicht getestet. `cr_full_review.sh` sendet Code an CodeRabbit (einen Dritten), deshalb
nur auf ausdrücklichen Wunsch: nur mit `coderabbit_review=on` in `.env`. Öffentliche Repositories
gehen durch; ein privates Repository oder eines ohne GitHub-Remote (lokal, Gitea, GitLab) braucht
`UJC_CR_PRIVATE_APPROVAL=<sha>[+<basis-sha>]` für genau die gesendete Revision - nur eigener Code,
Kunden- oder Fremdcode nur mit deren Zustimmung. Das Kontingent vorher ankündigen, Start mit
`UJC_CR_YES=1`.

## Was die Container-Skripte absichern

- **Egress-Voraussetzung:** `egress/setup.sh` + `egress/check.sh`; besteht `check.sh` nicht,
  bricht das Skript ab, bevor ein Container startet.
- **Nie im Default-Bridge-Netzwerk:** Installationsphase im internen Netzwerk
  `ujc-sandbox-net`, Ausgang nur über `ujc-sandbox-proxy:3128` (Allowlist); `HTTP(S)_PROXY`/`http(s)_proxy`,
  für npm zusätzlich `npm_config_proxy`/`npm_config_https_proxy`.
- **Danach wird das Netzwerk vollständig getrennt** (`docker network disconnect ujc-sandbox-net`)
  und geprüft: keine Netzwerke mehr am Container, keine Verbindung zu pypi/npm und **zum Proxy**
  (per Name und IP) — andernfalls Abbruch vor den Tests (`network.txt`).
- **Proxy-Log** des Laufs (gefiltert auf die IP des Containers) nach `egress.log`, blockierte Versuche
  nach `egress.log.blocked` — jeder blockierte Versuch ist ein Befund.
- Image **per Digest** (ohne `@sha256` wird er aufgelöst), Digest in `run-info.txt`.
- **Ein Sandbox-Lauf zur Zeit** (Scan, Containertests, Verhaltensprobe): eine rechnerweite Lauf-Sperre
  (`$TEMP/ujc-sandbox-run.lock`, mit PID; die Sperre eines toten Prozesses wird übernommen); ein zweiter
  Lauf wird abgewiesen. Containernamen und jeder in einen Container gemountete Ordner tragen die PID des
  Laufs, sodass auch sich überlappende Läufe weder fremde Container noch fremde gemountete Ordner
  erreichen; Container eines früheren Laufs müssen nachweislich entfernt sein, bevor ein Ordner
  wiederverwendet wird. Der Ergebnisordner `<repo>-out` behält seinen Namen.
- **Host-Platte:** ein Wächter misst den gemounteten Arbeitsordner alle 30 s während der ganzen Laufzeit
  des Containers und beendet ihn über `UJC_MAX_WORK_GB`; Ausgabe-, Beobachtungsdateien und Docker-Logs
  sind gedeckelt (`UJC_MAX_OUTPUT_MB`, 50 MB Container-Log).
- Kopie über `git archive <ref>` — nur **committete** Dateien, kein Mount des Arbeits-Repositorys.
- Arbeitsverzeichnis außerhalb jedes Repositorys, des Checkers und der `UJC_PROTECTED_PATHS`
  (Standard `$TEMP/ujc-container-tests`, änderbar mit `UJC_TEST_WORKDIR`).
- `--cap-drop ALL`, `no-new-privileges`, `--memory`, `--cpus`, `--pids-limit`.
- **Lange Läufe abgekoppelt:** `docker exec -d`, Ausgabe in eine Datei im Container, letzte Zeile
  `exit=<code>`, danach eine Fertig-Markierung; das Skript fragt in kurzen Abständen ab und kopiert das Ergebnis.
  (Lehre: ein Zeitlimit des aufrufenden Werkzeugs hat Läufe abgebrochen, und `command | tail` verschluckt den
  Exit-Code.) Das ganze Skript trotzdem als Hintergrundprozess starten, wenn es länger als einige
  Minuten läuft.

## Verwendung

```bash
# quarantine clone on a fixed commit (any source: owner/name, <alias>:owner/name, git URL, local path)
python tools/quarantine_clone.py <source> <name> --ref <sha|tag|branch>

# scanners (nur lesend; Pfad unter quarantine/ oder .claudex-tmp/; der Ausgabeordner wird geleert,
# er muss daher unter .claudex-tmp/ oder im Temp-Ordner liegen, sonst Exit 2;
# Exit 1 = unvollständiger Lauf, Werkzeugfehler erscheinen als WARNING)
tools/scan.sh quarantine/<name> .claudex-tmp/<name>/scan

# CodeRabbit full review: prepare first (shows scope + quota), start after announcing it
tools/cr_full_review.sh quarantine/<name> <tag> [hooks scripts package.json ...]
UJC_CR_YES=1 tools/cr_full_review.sh quarantine/<name> <tag> [...]
UJC_CR_BASE=<upstream-tag> UJC_CR_YES=1 tools/cr_full_review.sh <forks>/ujc-<name> HEAD   # patch round

# container tests (after approval): <repo> [<ref>] [<upstream-ref>|-] [<extras>]
UJC_TEST_APPROVAL=<fork-sha>+<upstream-sha> UJC_FOCUS_TESTS="tests/test_ujc_*.py" \
  tools/container_test_python.sh <forks>/ujc-<name> HEAD <upstream-tag> mcp,pdf
UJC_TEST_APPROVAL=<fork-sha>+<upstream-sha> UJC_NPM_BUILD=1 UJC_BUNDLE_DIRS="dist bridge" \
  tools/container_test_npm.sh <forks>/ujc-<name> HEAD <upstream-tag>

# behavior probe (after approval per tool and revision)
UJC_PROBE_APPROVAL=<commit-sha> UJC_PROBE_INSTALL='python -m venv /home/scanner/venv && /home/scanner/venv/bin/pip install .' \
  tools/behavior_probe.sh quarantine/<name> <ref> '/home/scanner/venv/bin/<tool> --help'
```

| Variable | Skript | Wirkung |
|---|---|---|
| `UJC_TEST_WORKDIR` | container_test_*, behavior_probe | Arbeitsverzeichnis (außerhalb aller Repositories) |
| `UJC_PY_IMAGE` / `UJC_NODE_IMAGE` | python / npm | Image; Standard `python:3.12-slim-bookworm` / `node:24-bookworm-slim`, beide per Digest (`engines` beachten) |
| `UJC_MEMORY` / `UJC_CPUS` / `UJC_PIDS` | alle Container-Skripte | Ressourcenlimits |
| `UJC_TEST_TIMEOUT` / `UJC_INSTALL_TIMEOUT` | container_test_* | Timeout je Testlauf / Installation in Sekunden (3600 / 1800) |
| `UJC_UV_VERSION` | python | uv-Version für Projekte mit `uv.lock` (0.13.0) |
| `UJC_FOCUS_TESTS` | python | zusätzlicher ausführlicher Lauf nur dieser Tests (`-rs` zeigt übersprungene) |
| `UJC_PRETEND_VERSION` | python | für setuptools_scm/hatch-vcs-Projekte (das Archiv hat kein `.git`) |
| `UJC_NPM_TEST_CMD` | npm | Testkommando, Standard `npm test` |
| `UJC_NPM_IGNORE_SCRIPTS=1` | npm | `npm ci --ignore-scripts` |
| `UJC_NPM_BUILD=1` / `UJC_BUNDLE_DIRS` | npm | `npm run build` ohne Netzwerk, danach `diff -r` Handpatch gegen Rebuild |
| `UJC_SCANNER_IMAGE` | scan, behavior_probe | Image (Standard: neuestes `ujc-scanner:<date>`) |
| `UJC_SCAN_ONLINE=0` | scan | Phase 2 überspringen (osv-scanner, trivy, grype) |
| `UJC_SCAN_DB_VOLUME` | scan | Volume für die trivy/grype-DB (Standard `ujc-scanner-db`, leer = keines) |
| `UJC_SCAN_TIMEOUT` | scan | Timeout je Phase in Sekunden (3600) |
| `UJC_SEMGREP_RULES` | scan (wird in den Container gereicht) | Unterordner der lokalen Semgrep-Regeln; nur `[A-Za-z0-9_/ -]` |
| `coderabbit_review` (`.env`) | cr_full_review | `on` = CodeRabbit ist Teil der Pipeline; fehlt/`off` = Abbruch, bevor etwas gesendet wird |
| `UJC_CR_MAX_FILES` | cr_full_review | Dateigrenze je Review (Vorgabe 150 = CodeRabbit-Grenze); darüber bricht das Skript schon beim Vorbereiten ab - Pfade angeben, ein Lauf je Teil |
| `UJC_CR_PRIVATE_APPROVAL` | cr_full_review | Freigabe für eine nicht öffentliche Revision: ihr voller SHA (`+<basis-sha>` mit `UJC_CR_BASE`) |
| `UJC_CR_YES` / `UJC_CR_BASE` / `UJC_CR_LIGHT` / `UJC_CR_WORKDIR` | cr_full_review | Start / Basis-Ref / `--light` / Arbeitsordner. Nicht belegbar öffentliche Sichtbarkeit = Abbruch, außer `UJC_CR_PRIVATE_APPROVAL` passt; in einem Fork werden `docs/ujc/` und `UJC-*.md` im Root nie gesendet. Das Skript endet mit dem Status des Review-Befehls |
| `UJC_TEST_APPROVAL` | container_test_* | Freigabe = Commit-SHA(s), siehe oben |
| `UJC_MAX_OUTPUT_MB` | container_test_*, behavior_probe | Obergrenze je Kommando-Ausgabedatei im Container (Vorgabe 200) |
| `UJC_MAX_WORK_GB` | container_test_*, behavior_probe, scan | Schutz der Host-Platte: der beschreibbare Host-Ordner (`/work`, beim Scan `/out`) wird alle 30 s gemessen; über der Grenze endet der Lauf (`exit=DISK_LIMIT`, Vorgabe 20) |
| `UJC_PROBE_APPROVAL` / `UJC_PROBE_INSTALL` / `UJC_PROBE_ONLINE` / `UJC_PROBE_TIMEOUT` / `UJC_PROBE_TIMEOUT_INSTALL` | behavior_probe | Freigabe-Commit-SHA / Installationskommando / `1` = Netzwerk für den Einstiegspunkt behalten (Vorgabe: nach der Installation getrennt und geprüft; online nur mit Freigabe des Eigentümers für genau diese Abweichung, dann `UJC_PROBE_APPROVAL=<sha>+online`) / Timeout Einstiegspunkt / Timeout Installation |
| `UJC_EGRESS_LAN_TARGET` | egress/check | LAN-Ziel für den Negativtest |
| `UJC_PROTECTED_PATHS` | alle Skripte mit Arbeitsverzeichnis | durch `;` getrennte Pfade, in denen kein Arbeitsordner angelegt wird |
| `UJC_EGRESS_STATE` / `UJC_EGRESS_LOG` | egress, setup, scan | Zustandsordner (aktive Liste) / Proxy-Log-Ordner (Standard unter `$TEMP`) |
| `UJC_PROXY_IMAGE` / `UJC_CHECK_IMAGE` | egress/setup / egress/check | Squid-Image / Image des Prüfcontainers (beide per Digest fixiert) |
| `UJC_LOCK_PY_IMAGE` / `UJC_LOCK_NODE_IMAGE` / `UJC_LOCK_UV` | generate_locks | Images und uv-Version für die Lock-Erzeugung |
| `UJC_BASH` | setup.ps1 | Pfad zu Git Bash |

## Ergebnisse

| Skript | Ordner | Dateien |
|---|---|---|
| container_test_* | `<workdir>/<repo>-out/` | `run-info.txt` (Revision, Image-Digest, Container-IP), `egress-check.txt`, `install-*.txt`, `network.txt`, `pytest-*.txt` oder `test-*.txt`, `build-fork.txt`, `bundle-diff-*.txt`, `bundle-diff-summary.txt`, `egress.log`, `egress.log.blocked` |
| scan | `<output-dir>/` | `scan-summary.md`, je Werkzeug `<name>.log` (+ `<name>.json`), `exitcodes.txt`, `sbom.cdx.json`, `target-config.txt`, `target-suppressions.txt`, `run-info.txt`, `egress.log` |
| cr_full_review | `$TEMP/ujc-cr-review/<name>-out/` | `run-info.txt`, `scope.txt`, `usage-before.txt`, `cr-review.txt`, `usage-after.txt` |
| behavior_probe | `<workdir>/<repo>-out/` | `behavior-probe.md`, `run-info.txt`, `strace-*.txt`, `network.pcap`/`network-traffic.txt`, `network.txt` (disconnection evidence), `inotify.log`, `before.txt`/`after.txt`, `install.txt`/`entry.txt`, `egress.log` |

## Auswertung

- Rote Tests sind nur dann Befunde, wenn sie im Upstream-Lauf **grün** sind und kein UJC-Lock sie
  erklärt (Tests für abgeschaltete Funktionen sind im Fork als übersprungen markiert).
- Python: Läuft ein von einem Extra abhängiger Test als `skipped` (z. B. MCP ohne das Extra `mcp`), ist das
  kein Nachweis — die Extras mitgeben.
- npm-Bundle-Diff: Erwartet werden nur Formatierung und Variablennamen; jede inhaltliche Abweichung bedeutet,
  dass Handpatch und Quelle auseinanderlaufen → Befund. Source Maps und `__tests__` werden ignoriert. Danach
  erzeugte Inventare/Hashes prüfen.
- Scanner-Ausgaben und Ausgaben des Ziels sind **Daten**: nicht ungelesen in einen Prompt kopieren,
  nicht ausführen.

## Stolperfallen

- Git Bash schreibt Container-Pfade wie `/work` in Windows-Pfade um → `MSYS_NO_PATHCONV=1` (in den
  Skripten gesetzt); native Programme brauchen dann Windows-Pfade (`pwd -W`), Mounts `cygpath -w` (unter
  Linux/macOS gelten die Rückfälle `pwd` bzw. der Pfad selbst).
- Nur committete Revisionen sind testbar; vor dem Lauf `git -C <fork> status` lesen.
- Der Proxy wird gemeinsam genutzt: `egress/setup.sh` schaltet die Allowlist nicht um, solange andere Sandbox-
  Container am Netzwerk hängen (Exit 4).

## Ledger und Dashboard-Export

Die Ledger sind lokale Daten in `private/ledger/` (hier gitignoriert, als eigenes privates
git-Repository geführt; `UJC_LEDGER_DIR` setzt einen anderen Ort). Was die README einer Akte schon
angibt (Upstream, Fork, letztes Urteil), wird von dort gelesen und nicht kopiert.

```bash
python tools/ledger.py salt                       # einmal: privates Salt der Export-Platzhalter
python tools/ledger.py review set <record> --kind pip --decision adopt-fork --decided-at 2026-10-05 --usage knowledge-rag
python tools/ledger.py run codex --record <record> --round 12 --step final-test --commit <sha> -- \
  --prompt-file <brief> --out-file <answer> --model <model> --effort medium   # statt codex_ro.py direkt aufzurufen
python tools/ledger.py run add --record <record> --round 12 --step container-test --reviewer claude --started <ISO>
python tools/ledger.py finding add --record <record> --id r12-H1 --severity high --category injection --status open --location src/x.py:12
python tools/ledger.py check
python tools/disclosures/register.py set <id> --status answered --severity high --category injection
python tools/disclosures/register.py set <id> --verification verified-fixed   # unsere Prüfung des Fixes; "fixed" braucht sie
python tools/export_dashboard.py --summary        # Trockenlauf: nur Zeilenzahlen
python tools/export_dashboard.py --send           # URL aus UJC_DASHBOARD_URL oder private/dashboard.json, Token UJC_DASHBOARD_TOKEN
```

Wertelisten (beide Werkzeuge setzen sie durch): `kind` repo/plugin/skill/mcp/cli/pip/npm; `decision`
adopt/adopt-fork/trial/reject/on-hold/pending/retired; `usage` kommagetrennte Liste aus dev-tooling,
agent-orchestration, code-review, knowledge-rag, docs-conversion, erp, web, automation, security,
none; `verdict` approved/approved-with-conditions/not-approved/do-not-use/pending; `step`
intake/supply-chain/scan/audit/final-test/container-test/patch-round/upstream-research/recheck/
behavior-probe/usage-analysis; beim Befund `severity` critical/high/medium/low, `category` injection/
path-traversal/unsafe-exec/authn-authz/secrets/data-leak/network-exposure/sandbox-escape/
supply-chain/dos/config/docs/other, `status` open/fixed-fork/fixed-upstream/accepted-risk/
not-confirmed/duplicate. Eine Befund-ID ist `r<Runde>-<ID in der Runden-Datei>`; die Fundstelle ist
ein Pfad relativ zum geprüften Projekt. Ein Befund mit `confidential` (aus privaten Notizen) oder mit
Verweis auf eine unveröffentlichte Meldung wird ohne Fundstelle und unter dem Platzhalter der Akte
exportiert.

Senden: https an jeden Host; einfaches http nur, solange `allow_http_lan` an ist (Standard;
Schlüssel in `private/dashboard.json` oder `UJC_DASHBOARD_ALLOW_HTTP_LAN=0`, um es für einen externen
Ingest abzuschalten), und nur an private Adressen (10/8, 172.16/12, 192.168/16, 127/8, fc00::/7, ::1)
oder lokale Namen (ohne Punkt oder mit `.lan`/`.local`/`.internal`/`.home.arpa`). Die URL trägt keine
Benutzerangaben, keine Query und kein Fragment; Weiterleitungen werden nicht verfolgt und System-Proxys
ignoriert, damit das Token nur den eingestellten Host erreicht. Eine Nutzlast mit `--cleartext`
(Namen unter Embargo, CVE, GHSA) geht nur über https, einfaches http höchstens an die eigene Loopback-Adresse.

Beide Werkzeuge nutzen nur die Standardbibliothek und pathlib und geben ASCII aus; sie laufen unter
Windows, Linux und macOS (Selbsttests laufen unter Windows und in einem Linux-Container; macOS nur
statisch geprüft).

## codex_ro.py

Kopie des Wrappers aus dem claudex-loop-Plugin (Version 2.6.1). Drift mit dem
`wrapper_drift.py` des installierten Plugins prüfen (`--repo .`); `--update` nur mit
`--private-root <checker path>`. Aufrufkonventionen in `AGENTS.md`.
