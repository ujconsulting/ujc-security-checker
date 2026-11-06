<!-- source: README.md sha256:4df25eae6e8f65c9bf44bfa8cf710a44c5bfbc3e61a34979b229fbac68ea6acb -->
[English](README.md) | [Deutsch](README_de.md)

# tools/disclosures - Befunde melden, Offenlegungen und den Posteingang verfolgen

Einfache Kommandozeilenwerkzeuge: Python 3.10+ (nur Standardbibliothek) plus die `gh`-CLI, aufgerufen aus dem
Checker-Root. Ablauf, Regeln, Schweregradklassen, Embargo: Skill
[`finding-disclosure`](../../.claude/skills/finding-disclosure/README_de.md).

| Werkzeug | schreibt nach außen? | Zweck |
|---|---|---|
| `forge.py list` / `check <alias> [--repo o/n]` | nein (GET) | Code-Hosts außer github.com: konfigurierte Forges (ohne Geheimnisse) sowie Erreichbarkeits- und Anmeldeprüfung; Modul für alle folgenden Werkzeuge (siehe „Andere Code-Hosts“) |
| `channel.py <o/r> [--file P --lines a-b] [--duplicates "..."] [--out F]` | nein (GET) | Default-Branch + SHA, Release, SECURITY.md, PVR, Kanalempfehlung, Datei im aktuellen Stand, Duplikate (`--policy` holt die Richtliniendateien über den festgehaltenen Commit-SHA) |
| `channel.py --policy <o/r> [--store <folder>] [--out <file>]` | nein (GET); speichert lokal | SECURITY.md (`.github/`, Root, `docs/` - Rangfolge von GitHub - sonst `<owner>/.github`) + referenzierte Richtlinien + CONTRIBUTING mit Sicherheitsabschnitt als Nachweis `private/records/<record>/disclosures/policy/SECURITY-<blob7>.md` (+ `.evidence.json` mit Blob-SHA, SHA-256, Commit); Checkliste (Versionen, Kanal, Pflichtinhalt, Modell/Geltungsbereich, Fristen, Test/Offenlegung) und ein Gerüst für das Entwurfsfeld `policy` |
| `leak_scan.py <draft>` / `--text <file>` | nein | KI-Hinweise, lokale Pfade, interne Adressen, Zugangsdaten, interne Namen (gemeinsame Sperrliste `private/public_check_denylist.txt`, optional zusätzlich `private/disclosures/leak_names.txt`) |
| `codex_check.py run\|finding\|exposure <draft> --source quarantine/<name>` / `status` / `config` | nein (Codex nur lesend über `tools/codex_ro.py`) | Codex-Gegenprüfung des ausgehenden Texts gegen den Upstream-Quelltext am referenzierten Commit - jede Aussage CONFIRMED / WRONG / OVERSTATED / NOT VERIFIABLE, letzte Zeile `CHECK: CONFIRMED` oder `CHECK: CORRECTIONS NEEDED`; Nachweis `private/repos/<record>/disclosures/checks/<id>.check`, gebunden an den Hash des Entwurfs. Nur aktiv mit `disclosure_codex_check=on\|critical` in der `.env`. `finding` validiert den Befund selbst (`FINDING: CONFIRMED` / `NOT CONFIRMED` / `SEVERITY WRONG`), `exposure` die Erreichbarkeit von außen (`EXPOSURE: UNSAFE` / `SAFE`) - siehe „Codex-Schranken“; `config` zeigt die wirksamen Schalter, Modelle und Efforts |
| `approval.py show/grant/status/revoke` | nein (GET für die Richtlinienprüfung) | hashgebundene Einmalfreigabe `private/repos/<record>/disclosures/approvals/<id>.approval`; verweigert ohne gültige Richtlinienprüfung, ohne die bestätigten Codex-Schranken (Textprüfung, Befundvalidierung, Exposure-Pass - je falls eingeschaltet) oder wenn die ID bereits im Register steht |
| `issue_submit.py <draft> [--submit]` | **ja**, nur mit Freigabe | öffentliches Issue, Kommentar, Reaktion im eigenen Repository (Kommentar/Labels/Schließen); auf GitLab auch ein vertrauliches Issue (`"confidential": true`) |
| `advisory_submit.py <draft> [--submit]` | **ja**, nur mit Freigabe | Private Vulnerability Reporting (nur GitHub-artige Forges) |
| `mail_report.py new/send/inbox/config`, `--check-connection` | **ja** (`send --send`), nur mit Freigabe | Mail über das eigene Security-Postfach (Adresse aus `.env`: `security_mail_address`, Absendername `security_mail_sender_name`, Vorgabe „Security Team“; nie im Repository; Versand mit dem Platzhalter wird verweigert); Postfach nur lesend. `send --send` legt vor dem SMTP-Versand eine Markierung `private/disclosures/sending/<id>.json` an und entfernt sie nach dem Registereintrag; solange sie existiert, wird ein neuer Versand verweigert (die Mail kann hinausgegangen sein - Gesendet-Ordner prüfen, von Hand abgleichen). `inbox` liest höchstens 200 Nachrichten je Lauf und speichert die höchste tatsächlich verarbeitete UID (der Rest wird als offen gemeldet); eine per Betreff/Message-ID einem Eintrag zugeordnete Nachricht ist ein ungeprüfter Hinweis |
| `register.py check/readme/new/publish/migrate/posted` | nein (publish: GET) | Register je Record (öffentlich + vertraulich), Übersichten `REGISTER.md` + `REGISTER_de.md`, Embargo aufheben; `migrate --record <name> [--dry-run]` verschiebt alte Wurzel-Einträge in den Record; `posted <draft> --url <link> [--reference R] [--created ISO] [--account A]` trägt eine **von Hand** gesetzte Meldung ein (z. B. Kommentar zu einem Security Advisory - es gibt keine REST-API) unter denselben Schranken wie ein Einreichwerkzeug (Felder, Leak-Scan, Richtlinie, Codex-Schranken, hashgebundene Freigabe für den Kanal des Entwurfs); https-Link in das Repository, Referenz aus dem Link (Entwurfsfeld `"advisory": "<GHSA>#<fragment>"`), ein Entwurf unter `private/` macht den Eintrag vertraulich; `new` kennt `--id`, `--confidential`, `--record` |
| `disclosure_watch.py [--flag] [--since D] [--no-mail] [--no-repos] [--no-save]` | nein (GET, EXAMINE) | Beobachtung: Offenlegungen, eigenes Repository, Postfach, Upstream-Repositories mit Wertklassifizierung (auch bei anderen Code-Hosts: Forge-Einträge; GitLab listet nur Issues; eigene Konten `forge_<alias>_accounts`). Hinweise, die auf Fremdtext beruhen (eine in einem Kommentar genannte #Nummer, eine per Betreff/Message-ID zugeordnete Mail), werden als ungeprüft gemeldet und setzen den Status nie weiter. Nichts aus einem privaten eigenen Repository und kein Eintrag mit Sicherheitsbegriffen in Text oder Kommentaren gelangt in den öffentlichen Bericht. Ein nicht lesbares eigenes Repository und eine erreichte Eintragsgrenze werden gemeldet (nicht lesbar: Exit 2; Grenze: die Markierung bleibt beim zuletzt verarbeiteten Eintrag) |
| `own_repo.py` | - | Modul: Klassifizierung und Reaktionsentwürfe für das eigene Repository |
| `own_repos_check.py [--accounts A ...] [--out F]` | nein (GET); schreibt die Übersichtsdatei `--out` (Vorgabe `disclosures/own_repos.md`) | eigene öffentliche Repositories: PVR, SECURITY.md, Adresse (Konten bei anderen Forges als `<alias>:<konto>`; wo ein Forge kein PVR hat, muss die SECURITY.md einen Kanal nennen) |
| `scheduled_task_setup.ps1 [-Install] [-Remove] [-Time HH:MM] [-DayOfWeek <Tag>]` | lokal (Aufgabenplanung) | tägliche Beobachtung, mit `-DayOfWeek` wöchentlich - **nur nach Freigabe** |

Ablage (Regel seit 12.10.2026): `disclosures/` und `private/disclosures/` in der Wurzel enthalten nur,
was zum Checker selbst gehört (Eingang des eigenen Repositorys, `own_repos.md`, `watch_config*`,
eigene Befunde, `seen.json`, `mail_status.json`, `NEW.flag`, `reactions.jsonl`, `leak_names.txt`).
Alles zu einem geprüften Repository liegt bei seinem Record, und nichts davon wird versioniert
(nur die Kurzfassung `repos/<record>/README.md` + `README_de.md`; seit 06.11.2026): der frühere
öffentliche Teil in `private/records/<record>/disclosures/` (`register.json`, erzeugte `REGISTER.md` +
`REGISTER_de.md`, `reports/`, Entwürfe nicht kritischer Befunde, `policy/`), die nicht vertraulichen
Berichte des Checkers selbst in `private/disclosures/public-reports/`, vertraulich in `private/repos/<record>/disclosures/` (`register.json`, `REGISTER.md`,
`approvals/`, `checks/`, `reports/`, `reply-drafts/`, kritische Entwürfe). Der Record eines Eintrags
ist das Feld `record`, sonst der Ordner des Entwurfs, sonst der Record, dessen README das Repository
als „Upstream“ nennt; eine Meldung an ein fremdes Repository ohne Record wird abgelehnt, bevor
irgendetwas hinausgeht (`_submit.record_or_abort`), eigene Repositories (`own_repos` in der
Watch-Konfiguration) bleiben in der Wurzel. `disclosure_watch.py` schreibt Berichte und
Antwortentwürfe ebenso je Record. Alle Orte werden zur Laufzeit aus dem aktuellen Registerort
abgeleitet, ein Selbsttest berührt die echten Übersichten also nie.

Entwurfsformat: Markdown mit internem Kopf, einem ```` ```json disclosure ````-Block und der Markierung
`<!-- TEXT -->`; alles nach der Markierung geht byteweise hinaus. Vorlagen:
`templates/advisory-draft.md`, `templates/issue-draft.md`, `templates/security-report-mail.md`.
Die Markierung muss genau einmal und nach dem JSON-Block vorkommen, sonst wird der Entwurf abgelehnt.

Fail-closed-Regeln der Einreichungswerkzeuge: Die Richtlinienprüfung nutzt immer das `repo` der
Meldung selbst (`policy.repo` darf nur `<owner>/.github` nennen); ein HTTP 403 von GitHub ist ein
Fehler, nie „nicht gefunden“ (nur 404 heißt „keine SECURITY.md“); bei einem kritischen Befund als
öffentliches Issue/Kommentar zählen die „exploit detail?“-Funde des Leak-Scans (PoC, Payload,
Reverse Shell, Exploit) als Fehler; der Leak-Scan deckt jedes gesendete Feld ab (Advisory: Summary,
Beschreibung sowie serialisierte `vulnerabilities`, cvss, cwe_ids; Reaktion: Labels);
`register.py publish` verschiebt einen Entwurf nur, wenn sein Registerpfad eine reguläre `.md`-Datei
ohne Symlink unter `private/disclosures/` oder `private/repos/` ist; Registerschreibzugriffe sind
atomar und über eine Sperrdatei `private/disclosures/register.lock` serialisiert (veraltet nach
10 Minuten).

Richtlinienprüfung (verpflichtend für Issue, Kommentar, Advisory, E-Mail): jeder Entwurf trägt das Feld
`policy` in seinem JSON-Block (Format: `_submit.py`, Vorlagen unter `templates/`).
`approval.py grant`, die Submit-Werkzeuge und `mail_report.py send` brechen - bereits im Trockenlauf -
mit Exit 1 ab, wenn es fehlt, ein Pflichtinhalt nicht `true` ist, `result` nicht `report` ist
oder die aktuelle Upstream-SECURITY.md (GET, Blob-SHA) vom geprüften Stand abweicht („policy
changed, check again“). Ohne SECURITY.md: `blob_sha: null`, die Bewertung bleibt verpflichtend.
Eine zugesagte Antwortzeit (`response_days` / `response_workdays`) geht in das Register;
`disclosure_watch.py` meldet „deadline passed without response“.

Codex-Gegenprüfung (optional, je Projekt in der `.env` eingeschaltet: `disclosure_codex_check=on`,
`disclosure_codex_model` Vorgabe `gpt-6.1-sol`, `disclosure_codex_effort` Vorgabe `medium`,
Vorlage `.env.example`): **kein Audit**. Codex bekommt nur den Text, der hinausgeht (Kopffelder +
Text nach der Markierung, nie den internen Teil), und prüft jede Aussage darin gegen einen
Quarantäne-Klon auf einem Commit aus `upstream_ref`; nach neuen Befunden sucht es nicht. Ist sie
eingeschaltet, verweigern `approval.py grant` und alle Submit-Werkzeuge mit Exit 1, solange kein
Nachweis für genau den aktuellen Hash des Entwurfs vorliegt, der mit dem eingestellten Modell/Effort
lief und dessen unveränderte Codex-Ausgabe mit `CHECK: CONFIRMED` endet. Ein korrigierter Entwurf hat
einen neuen Hash und braucht eine neue Gegenprüfung und eine neue Freigabe. Reaktionen im eigenen
Repository sind keine Meldungen und brauchen keine.

Codex-Schranken (claudex-Anbindung): neben der Textprüfung prüfen zwei weitere Schranken den Befund
selbst, jede mit eigenem Schalter (`off` | `critical` | `all`), Modell und Effort. Steht in der `.env`
kein Modell, wird die Rollenkonfiguration von claudex-loop befragt (`claudex_loop_dir` ->
`claudex_roles.py --spec <role>`), sonst gilt die Vorgabe `gpt-6.1-sol` / `medium`.

| Schranke | Schalter / Modell / Effort | Frage | Besteht mit |
|---|---|---|---|
| Textprüfung (`run`) | `disclosure_codex_check=on\|critical\|off`, `disclosure_codex_channels`, `disclosure_codex_timeout` | stimmt jede Aussage im ausgehenden Text? | `CHECK: CONFIRMED` |
| Befundvalidierung (`finding`) | `claudex_finding_check`, `claudex_finding_model`, `claudex_finding_effort` (Rolle `code-review`) | ist der Befund am referenzierten Commit real, tragen Voraussetzungen, Schweregradklasse und Bewertung, ist er laut Richtlinie beabsichtigt? | `FINDING: CONFIRMED` (`NOT CONFIRMED` und `SEVERITY WRONG` blockieren) |
| Exposure-Pass (`exposure`) | `claudex_exposure_check`, `claudex_exposure_model`, `claudex_exposure_effort` (Rolle `exposure-review`) | ist der betroffene Code von außerhalb der Maschine erreichbar, und von wem? | ein zum Entwurfsfeld `exposure` passendes Urteil (`network` = `EXPOSURE: UNSAFE`, `local` = `SAFE`); ein kritischer Befund mit `SAFE` braucht `"exposure_override": "<Begründung>"` |

Die Nachweise von Befund und Exposure (`private/repos/<record>/disclosures/checks/<id>.finding.check`,
`<id>.exposure.check`) sind an einen Digest der Befundfelder gebunden (finding, severity, rating,
`upstream_ref`, exposure, repo, forge), nicht an den Wortlaut: eine Textkorrektur braucht nur eine neue
Textprüfung. `approval.py grant` und jedes Submit-Werkzeug prüfen alle drei Schranken (`_submit.py
codex_check_or_abort`); immer nur ein Codex-Lauf, nie parallel. Exit 4 = Codex-Kontingent erschöpft
(nichts protokolliert, später erneut), Exit 3 = Codex konnte keine Befehle ausführen (die Prüfung hat
nicht stattgefunden). `--source` ist ein Klon unter `quarantine/` auf einem Commit aus `upstream_ref`
(`tools/quarantine_clone.py`, auch für Gitea, GitLab und andere Git-Server).

Andere Code-Hosts (`forge.py`): außer github.com sprechen die Werkzeuge GitHub Enterprise / eigene
GitHub-Server, Gitea (Forgejo), GitLab (gitlab.com oder selbst betrieben, Untergruppen) und reine
Git-Server ohne API an, als `<alias>:owner/name` (GitLab auch `<alias>:group/sub/name`). Der Alias
stammt aus einem Block `forge_<alias>_*` in der `.env` (Vorlage `.env.example`: `type`, `url`, `token`,
`ca_bundle`, `tls_verify`, `allow_http`, `write`, `accounts`, `timeout`). Die Werkzeuge sprechen weiter
GitHub-artige Pfade; `forge.py` übersetzt sie für Gitea und GitLab. Fehlt einem Forge ein Merkmal (PVR,
Advisories, Alerts), lautet die Antwort „nicht verfügbar“. `write=off` ist die Vorgabe: die
Submit-Werkzeuge schreiben nur auf einen Forge mit `forge_<alias>_write=on`, über dieselbe
hashgebundene Freigabe; das Token geht nur an den konfigurierten API-Host. Typ `git` schreibt nie und
führt nie Code aus dem Repository aus.

```bash
python tools/disclosures/forge.py list               # configured forges, no secrets
python tools/disclosures/forge.py check <alias>      # reachability + login, GET only
python tools/disclosures/channel.py lan:tools/scanner --duplicates "path traversal"
```

Optionale Entwurfsfelder (JSON-Block): `forge` (Alias; fehlt = github.com), `confidential` (`true` =
vertrauliches GitLab-Issue für einen kritischen Befund; der Entwurf muss unter `private/` liegen und
bleibt bis `register.py publish` im vertraulichen Register; Gitea kennt keine vertraulichen Issues und
verweigert), `exposure` (`"network"` | `"local"`, Eingabe des Exposure-Passes), `exposure_override`
(Begründung, siehe oben).

Keine doppelte Einreichung: ein Entwurf, dessen `id` bereits im Register steht (öffentlicher oder vertraulicher
Teil), wird nie erneut eingereicht. Der Trockenlauf gibt `ALREADY SUBMITTED: ...` aus und endet mit 0,
`--submit` / `--send` verweigern mit Exit 1, `approval.py grant` verweigert mit Exit 1.

Der Trockenlauf ist überall der Standard. Schreibende GitHub-Aufrufe gibt es nur in
`_common.gh_post` (POST, PATCH zum Schließen eigener Issues), SMTP und IMAP APPEND nur in
`mail_report.py send`; sie laufen alle erst nach `check_approval()` mit passender SHA-256
und verbrauchen die Freigabe - VOR dem externen Aufruf (ein Absturz nach dem Senden hinterlässt keine
wiederverwendbare Freigabe; scheitert der Aufruf, braucht es eine neue Freigabe - erst das Ziel prüfen).
Der Nachweis der Codex-Gegenprüfung bleibt erhalten. Das Postfach wird nur lesend geöffnet (EXAMINE, BODY.PEEK).

Format der Freigabedatei (`private/repos/<record>/disclosures/approvals/<id>.approval`):

```text
action=<issue|comment|advisory|email|reaction>
sha256=<SHA-256 of the draft file>
granted=<ISO time>
note=<who approved when>
```

Umgebungsvariablen: `UJC_VAULT_ENV` (Ort von `vault_env.py`, nur Postfach),
`security_mail_*` (überschreiben die `.env`), `UJC_CHECKER_ROOT` (anderer Root, für Tests).

Selbsttests (ohne Netzwerk):

```bash
python tools/disclosures/leak_scan.py --self-test
python tools/disclosures/advisory_submit.py --self-test
python tools/disclosures/mail_report.py --self-test
python tools/disclosures/disclosure_watch.py --self-test
python tools/disclosures/approval.py --self-test      # policy check, approval, dry run, double submission
python tools/disclosures/codex_check.py --self-test   # switches, hash binding, three gates in approval and submit
python tools/disclosures/forge.py --self-test         # address parsing, path translation, safety rules
python tools/disclosures/channel.py --self-test       # policy heuristic, blob SHA
```

Exit-Codes: 0 in Ordnung / nichts Neues, 1 Befund (Leak, Neuigkeit, Lücke, keine Freigabe, bereits eingereicht
bei `--submit`), 2 Bedienfehler (gh nicht angemeldet, Datei fehlt, Verbindung fehlgeschlagen).
Die Konsolenausgabe ist ASCII.
