<!-- source: SETUP.md sha256:ed89d1ffdb0efd79b6034c25b302a3e785cbe0fcc3ce29dded975b00f74e8101 -->
[English](SETUP.md) | [Deutsch](SETUP_de.md)

# Einrichtung

Vollständige Installation der Prüfstation in der richtigen Reihenfolge. Jeder Schritt nennt den
Befehl und das erwartete Ergebnis. Befehle laufen im Wurzelverzeichnis des Repositorys; unter
Windows in Git Bash, sofern nicht PowerShell genannt ist. Auf dem Host wird nur installiert, was
man in Schritt 1 selbst installiert.

## 1. Voraussetzungen

| Programm | Mindestens | Gebraucht für | Prüfung |
|---|---|---|---|
| Python | 3.10 | alle Werkzeuge in `tools/` (nur Standardbibliothek) | `python --version` |
| git | jede aktuelle Version | alles | `git --version` |
| GitHub CLI `gh` | angemeldet, Scopes `repo` und `security_events` | Meldungen, Beobachtung, Sichtbarkeitsprüfungen | `gh auth status` |
| Docker Engine / Docker Desktop | 28 (isoliertes Gateway des Sandbox-Netzes), Linux-Container, amd64 | Sandbox, Scanner, Containertests | `docker version` |
| bash | 4.4 (Git Bash unter Windows; macOS bringt 3.2 mit: `brew install bash`) | alle Shell-Skripte | `bash --version` |
| ShellCheck | 0.11, **Pflicht** (`winget install koalaman.shellcheck`, `apt install shellcheck`, `brew install shellcheck`) | Prüfung aller Shell-Skripte und Git-Hooks; `tools/setup.sh` bricht ohne es ab (Schritte 1 und 6) | `shellcheck --version` |
| Windows PowerShell | 5.1 | nur die geplante Beobachtungsaufgabe und `tools/setup.ps1` | `$PSVersionTable.PSVersion` |
| CodeRabbit CLI | optional | `tools/cr_full_review.sh` | `coderabbit --version` |
| Codex CLI | optional, 0.162.1 (Wrapper 2.6.1, Modell gpt-6.1-sol) | zweiter Reviewer über `tools/codex_ro.py` | `codex --version` |

Erwartetes Ergebnis: jeder Befehl antwortet mit einer Version mindestens auf dem genannten Stand.
`gh auth status` zeigt die Scopes `repo` und `security_events` (fehlende ergänzen mit
`gh auth refresh -s repo,security_events`). Ohne `security_events` meldet die Beobachtung
Dependabot- und Code-Scanning-Warnungen als „nicht verfügbar“; alles andere funktioniert.

`requirements.txt` enthält kein Pflichtpaket. `pip install -r requirements.txt` ist optional und
installiert nichts; das einzige optionale Paket (`paramiko`, für den optionalen Secret-Lader aus
Schritt 3) ist dort auskommentiert.

## 2. Klonen

```bash
git clone https://github.com/ujconsulting/ujc-security-checker.git
cd ujc-security-checker
git config core.autocrlf false
python tools/public_check.py --self-test
```

Erwartetes Ergebnis: `public_check self-test: OK`. Alle Dateien sind LF; mit
`core.autocrlf false` wandelt git sie nicht um (die Prüfung meldet CR-Zeilenenden als Befund).

## 3. Lokale Konfiguration: `.env` und Secrets

Nur nötig für das Postfach der Melde-Werkzeuge (Meldungen per Mail senden, Antworten lesen).

```bash
cp .env.example .env
```

Host, Port, Verschlüsselung (`ssl` = implizites TLS, `tls` = STARTTLS) und Benutzernamen für
eingehende (IMAP) und ausgehende (SMTP) Post eintragen. `.env` ist gitignoriert. Für die
Passwörter gibt es zwei Wege:

1. **Umgebungsvariablen** - `security_mail_password_in` und `security_mail_password_out` (und
   nach Bedarf alle anderen `security_mail_*`-Schlüssel) in der Umgebung setzen. Bereits gesetzte
   Werte haben Vorrang vor `.env`; sind alle Schlüssel gesetzt, wird `.env` gar nicht gelesen.
2. **Optionaler Secret-Lader** - `UJC_VAULT_ENV` auf ein Python-Modul `vault_env.py` (oder dessen
   Ordner) setzen, das `load_vault_env(path, override=False)` bereitstellt: es liest die
   `.env`-Datei, löst Platzhalter wie `${vault:<projekt>/<schlüssel>}` aus dem eigenen
   Secret-Speicher auf und setzt die Werte in `os.environ`. Der Lader gehört nicht zu diesem
   Repository; ob er `paramiko` braucht, hängt vom Speicher ab.

Erwartetes Ergebnis:

```bash
python tools/disclosures/mail_report.py config
```

gibt `OK: configuration complete (IMAP ..., SMTP ...)` aus. Werte werden nie ausgegeben.

## 4. Verbindung zum Postfach

```bash
python tools/disclosures/mail_report.py --check-connection
```

Erwartetes Ergebnis: `IMAP: login OK (...), EXAMINE INBOX: <n> messages`, `IMAP: Sent folder: ...`
und `SMTP: EHLO + login OK (...), QUIT - nothing sent`. Das Postfach wird nur lesend geöffnet; es
wird nichts gesendet. Eine Zeile `ERROR: IMAP: ...` oder `ERROR: SMTP: ...` nennt die fehlerhafte
Seite (Exit 2).

## 4b. Code-Hosts (Forges) und claudex-Schalter

Nur nötig für Repositories, die nicht auf github.com liegen (GitHub Enterprise / eigener GitHub-Server,
Gitea oder Forgejo, GitLab, reiner Git-Server), und für die Codex-Schranken. Je Code-Host ein Block
`forge_<alias>_*` in der `.env` - siehe den Abschnitt „Code hosts“ in `.env.example` (`type`, `url`,
`token` als `${vault:...}`-Verweis, optional `ca_bundle`, `tls_verify`, `allow_http`, `write`,
`accounts`). Schreiben ist standardmäßig aus (`write=off`). Prüfen:

```bash
python tools/disclosures/forge.py list              # configured forges, no secrets
python tools/disclosures/forge.py check <alias>     # reachability + login (GET only)
```

Die Schalter der Codex-Schranken (`disclosure_codex_check`, `claudex_finding_check`,
`claudex_exposure_check`, `claudex_audit_mode`, Modelle und Efforts, `claudex_loop_dir`) stehen im
Abschnitt „claudex“ der `.env.example`; die wirksamen Werte zeigt
`python tools/disclosures/codex_check.py config`. Quarantäne-Klone aus beliebiger Quelle:
`python tools/quarantine_clone.py <source> <name> --ref <ref>`.

## 5. Sandbox: Egress-Netz, Proxy, Scanner-Image

Ein Einstiegspunkt, idempotent (Skill [`sandbox-setup`](../.claude/skills/sandbox-setup/README_de.md)):

```bash
tools/setup.sh --check      # nur Status, ändert nichts
tools/setup.sh              # einrichten oder ergänzen (erster Lauf: einige Minuten, ~1 GB Downloads)
tools/setup.sh --rebuild    # Proxy neu anlegen, Image ohne Cache neu bauen
tools/setup.sh --remove     # Abbau: Proxy, Netz, Scanner-Images, DB-Volume, Zustand
```

Windows PowerShell: `.\tools\setup.ps1 --check` (findet Git Bash, sonst `UJC_BASH` setzen).

Erwartetes Ergebnis von `tools/setup.sh` und danach von `tools/setup.sh --check`: sechs Schritte
mit `OK`-Zeilen und als letzte Zeile `RESULT: sandbox ready (image ujc-scanner:<datum>)`, Exit 0.
Schritt 3 startet `tools/egress/check.sh` und muss mit `RESULT: all checks passed` enden; sonst
bricht das Skript ab und startet nichts weiter. Ohne LAN-Ziel meldet `check.sh`
`NOTE: no LAN target configured ...` und prüft stattdessen das Gateway des Docker-Bridge-Netzes.

Optionale lokale Einstellungen (gitignoriert, Zeilen `UJC_<NAME>=<wert>`):

| Datei | Zeile | Wirkung |
|---|---|---|
| `private/egress.conf` | `UJC_EGRESS_LAN_TARGET=<ip>:<port>` | ein echter Dienst im eigenen LAN für den Negativtest |
| `private/environment.conf` | `UJC_PROTECTED_PATHS=<pfad>;<pfad>` | Ordner, unter denen die Skripte nie Arbeitsverzeichnisse anlegen |
| `private/environment.conf` | `UJC_BASH=<pfad zu bash.exe>` | Git Bash für `setup.ps1` |

`tools/setup.sh --remove` bricht ab, solange Sandbox-Container am Netz hängen; es entfernt nur
Objekte nach Namen und behält Proxy-Logs und Basis-Images.

## 6. Codex-Skills

Die Skills liegen in `.claude/skills/`; Codex CLI findet sie unter `.agents/skills/`.

```bash
python tools/codex_skills_sync.py          # Spiegel schreiben
python tools/codex_skills_sync.py --check  # nur prüfen
```

Erwartetes Ergebnis: `OK: <n> skills, 0 deviations`, Exit 0. Skills, die git ignoriert (nur lokale
Skills), werden ebenfalls gespiegelt, aber als `LOCAL ONLY` gemeldet und nicht gezählt.

Codex selbst: im Wurzelverzeichnis des Repositorys starten (dann lädt es `AGENTS.md`); Reviews nur
über den nur lesenden Wrapper, z. B. `python tools/codex_ro.py --version`.

## 7. Git-Hooks (Öffentlich/privat-Prüfung)

Die Prüfung `tools/public_check.py` läuft vor jedem Commit (`.githooks/pre-commit`, mit `--staged`:
geprüft wird der Index, also genau das, was committet würde, nicht der Arbeitsbaum) und vor jedem
Push (`.githooks/pre-push`, mit `--rev <sha>` für jeden Commit, der gepusht wird, entnommen den
Ref-Zeilen, die git auf stdin übergibt, plus `--history`: geprüft werden die Bäume der gepushten
Commits und die ganze Historie, gelesen über git, sodass uncommittete oder unversionierte Dateien
des Arbeitsbaums nie einen Push blockieren; Dateien, die getrackt sind, obwohl die `.gitignore`-Dateien des Commits sie ausschließen, werden ebenfalls gemeldet; ohne brauchbare Ref-Zeile wird `HEAD` geprüft, nie
nichts). Ein Wagenrücklauf (CR) ist ein Befund, außer in Dateien, deren Zeilenende beim Auschecken
absichtlich CRLF ist (`*.ps1`, `*.bat`, `*.cmd` in `.gitattributes`; die Prüfung fragt
`git check-attr`); ein BOM ist immer ein Befund. Dateien, die sich nicht prüfen lassen (Binärdateien
außer gängigen Bild-/Schrift-/PDF-Typen, oder über 5 MiB), sind Befunde. Die Hooks nur für dieses Repository einschalten:

```bash
git config core.hooksPath .githooks
```

Erwartetes Ergebnis: `git config --get core.hooksPath` gibt `.githooks` aus; der nächste
`git commit` zeigt `pre-commit: public/private gate ...` und `TREE: 0 findings (none)`. Ein Befund
blockiert den Commit (Exit 1) und nennt Datei, Zeile und Prüfung.

**Verkettung mit vorhandenen Hooks.** Ein lokaler `core.hooksPath` ersetzt den globalen; deshalb
rufen die Skripte in `.githooks/` den bisherigen Hook auf, mit denselben Argumenten und derselben
Standardeingabe:

1. `UJC_CHAINED_HOOKS_PATH`, falls gesetzt (ein Ordner mit den eigenen Hooks),
2. sonst den globalen oder System-`core.hooksPath` (`git config --global --get core.hooksPath`),
3. sonst `.git/hooks/<hook>` dieses Klons.

Der bisherige Hook läuft erst, wenn die Prüfung bestanden ist; sein Exit-Code wird zum Ergebnis.
Gibt es keinen bisherigen Hook, wird nichts verkettet; ist einer eingestellt, aber unbrauchbar
(nicht ausführbar oder Ordner nicht auflösbar), bricht der Hook mit einem Fehler ab, statt ihn
zu überspringen.
Die globale Konfiguration wird nie geändert. Unter Windows beim Committen von Hook-Änderungen das
Ausführungsrecht erhalten:
`git update-index --chmod=+x .githooks/pre-commit .githooks/pre-push .githooks/_run_gate.sh`.

Manuelle Läufe:

```bash
python tools/public_check.py                 # Arbeitsbaum
python tools/public_check.py --staged        # der Index, wie ihn der pre-commit-Hook prüft
python tools/public_check.py --rev HEAD      # der Baum eines Commits, über git gelesen (pre-push)
python tools/public_check.py --history       # zusätzlich jeder Commit und jede Commit-Message
python tools/public_check.py --stamp README_de.md   # Quell-Hash nach dem Übersetzen erneuern
```

Optionale private Listen (gitignoriert): `private/public_check_denylist.txt` (interne Namen, einer
je Zeile, `re:` für einen regulären Ausdruck; werden nie ausgegeben, nur „denylist entry #N“) und
`private/public_check_allow.txt` (eigene öffentliche Repositories, die genannt werden dürfen). Der
Leak-Scan der Meldungen liest dieselbe Sperrliste.

## 8. Geplante Beobachtungsaufgabe (Windows, erst nach Entscheidung des Auftraggebers)

Die tägliche Beobachtung von Meldungen, Eingang und Postfach wird erst eingerichtet, wenn der
Auftraggeber sie freigegeben hat.

```powershell
.\tools\disclosures\scheduled_task_setup.ps1                                  # Probelauf, zeigt nur an
.\tools\disclosures\scheduled_task_setup.ps1 -Install -Time 08:30 -VaultEnv <pfad>
.\tools\disclosures\scheduled_task_setup.ps1 -Remove
```

Erwartetes Ergebnis: der Probelauf ändert nichts; `-Install` legt die Aufgabe
`UJC-Disclosure-Watch` an, die täglich `python tools/disclosures/disclosure_watch.py --flag`
startet. Bei Neuigkeiten oder Fehlern entsteht `private/disclosures/NEW.flag` und eine
Sprechblase erscheint; Protokoll `private/disclosures/watch.log`. `-VaultEnv` ist nur für das
Postfach nötig (Schritt 3). Manueller Lauf: `python tools/disclosures/disclosure_watch.py`
(Exit 0 nichts Neues, 1 Neuigkeiten, 2 Fehler).

## 9. Bevor das Repository öffentlich wird

In dieser Reihenfolge (Skill [`finding-disclosure`](../.claude/skills/finding-disclosure/README_de.md),
Abschnitt „Own public repositories“):

1. **Private Vulnerability Reporting** einschalten (GitHub: Settings -> Advanced Security).
2. Prüfen: `python tools/disclosures/own_repos_check.py` listet das Repository mit `pvr=on`.
3. Erst dann auf [`SECURITY.md`](../SECURITY.md) verlassen, die genau auf diesen Kanal zeigt.
4. Prüfung über die ganze Historie: `python tools/public_check.py --history` muss mit 0 enden.

## 10. Abnahme-Checkliste

- [ ] `python tools/public_check.py --self-test` -> `public_check self-test: OK`
- [ ] `python tools/public_check.py` -> Exit 0 (`TREE: 0 findings`)
- [ ] `python tools/codex_skills_sync.py --check` -> Exit 0
- [ ] Selbsttests der Melde-Werkzeuge, jeweils Exit 0:
      `python tools/disclosures/leak_scan.py --self-test`,
      `python tools/disclosures/approval.py --self-test`,
      `python tools/disclosures/channel.py --self-test`,
      `python tools/disclosures/advisory_submit.py --self-test`,
      `python tools/disclosures/mail_report.py --self-test`,
      `python tools/disclosures/disclosure_watch.py --self-test`,
      `python tools/codex_skills_sync.py --self-test`
- [ ] `python tools/disclosures/register.py check` -> `0 errors`
- [ ] `tools/setup.sh --check` -> `RESULT: sandbox ready`
- [ ] `gh auth status` -> angemeldet, Scopes `repo`, `security_events`
- [ ] optional: `python tools/disclosures/mail_report.py --check-connection` -> IMAP und SMTP OK
- [ ] `git config --get core.hooksPath` -> `.githooks` (falls die Hooks eingeschaltet wurden)
