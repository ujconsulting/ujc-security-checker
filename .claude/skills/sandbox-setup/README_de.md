<!-- source: README.md sha256:687ebac479b43acde1ba05b4585a447f05cec1d040389a93ab5c71779896184b -->
[English](README.md) | [Deutsch](README_de.md)

# sandbox-setup

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Richtet die Sandbox auf einem Rechner mit Docker über einen idempotenten Einstiegspunkt ein, prüft,
erneuert und entfernt sie: `tools/setup.sh` (Windows: `tools/setup.ps1`) - das interne Netz
`ujc-sandbox-net`, den Squid-Egress-Proxy `ujc-sandbox-proxy` mit seiner Allowlist, die
Egress-Prüfung und das Scanner-Image `ujc-scanner:<datum>`. Außer ShellCheck (Pflicht, prüft die
eigenen Skripte dieses Repositorys) wird auf dem Host nichts installiert; alle Scanner liegen im Image.

## Wann

- Ersteinrichtung auf einem Rechner;
- vor einem Scannerlauf, Containertest oder einer Verhaltensprobe (Statusprüfung);
- `setup.sh` oder `check.sh` meldet einen Fehler;
- Scanner-Versionen oder Lock-Dateien haben sich geändert (Neubau);
- die Sandbox soll entfernt werden.

## Ablauf

Sechs Schritte in fester Reihenfolge, Abbruch beim ersten Fehler: (1) Voraussetzungen (Docker mit
Linux-Containern auf amd64, bash 4.4+, git, ShellCheck), (2) Egress-Netz und Proxy, (3) `tools/egress/check.sh` -
Prüfungen in beide Richtungen, nicht grün = Abbruch, (4) Scanner-Image (nur gebaut, wenn sich der
Repository-Stand geändert hat), (5) jedes Werkzeug im Image startet einmal ohne Netz, (6)
Shell-Skripte und Git-Hooks bestehen `bash -n` und `shellcheck -S warning`, Basis-Images per Digest vorhanden.

## Befehle

```bash
tools/setup.sh --check     # nur Status, ändert nichts; Exit 0 = bereit
tools/setup.sh             # einrichten oder ergänzen
tools/setup.sh --rebuild   # Proxy neu anlegen, Image ohne Cache neu bauen
tools/setup.sh --remove    # Abbau (nur Objekte nach Namen; Logs und Basis-Images bleiben)
```

```powershell
.\tools\setup.ps1 --check  # Windows: findet Git Bash (oder UJC_BASH), reicht durch
```

Optionale lokale Einstellungen in `private/egress.conf` (`UJC_EGRESS_LAN_TARGET`) und
`private/environment.conf` (`UJC_PROTECTED_PATHS`, `UJC_BASH`).

## Beispiel

Nach einem Neustart von Docker Desktop meldet `tools/setup.sh --check` „proxy ujc-sandbox-proxy
not running“; `tools/setup.sh` startet ihn wieder, Schritt 3 besteht, die letzte Zeile lautet
`RESULT: sandbox ready (image ujc-scanner:<datum>)`.

## Siehe auch

[`docs/SETUP_de.md`](../../../docs/SETUP_de.md), [`tools/egress/README_de.md`](../../../tools/egress/README_de.md),
[`tools/scanner-image/README_de.md`](../../../tools/scanner-image/README_de.md),
[`docker-sandbox`](../docker-sandbox/README_de.md).
