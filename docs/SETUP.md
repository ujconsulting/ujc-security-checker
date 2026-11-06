[English](SETUP.md) | [Deutsch](SETUP_de.md)

# Setup

Complete installation of the review station, in order. Every step names the command and the
expected result. Commands run from the repository root; on Windows in Git Bash unless PowerShell
is named. Nothing here installs software on the host except what you install yourself in step 1.

## 1. Prerequisites

| Program | Minimum | Needed for | Check |
|---|---|---|---|
| Python | 3.10 | all tools in `tools/` (standard library only) | `python --version` |
| git | any recent version | everything | `git --version` |
| GitHub CLI `gh` | logged in, scopes `repo` and `security_events` | disclosures, watch, visibility checks | `gh auth status` |
| Docker Engine / Docker Desktop | 28 (isolated gateway of the sandbox network), Linux containers, amd64 | sandbox, scanners, container tests | `docker version` |
| bash | 4.4 (Git Bash on Windows; macOS ships 3.2: `brew install bash`) | all shell scripts | `bash --version` |
| ShellCheck | 0.11, **required** (`winget install koalaman.shellcheck`, `apt install shellcheck`, `brew install shellcheck`) | lint of all shell scripts and git hooks; `tools/setup.sh` stops without it (steps 1 and 6) | `shellcheck --version` |
| Windows PowerShell | 5.1 | only the scheduled watch task and `tools/setup.ps1` | `$PSVersionTable.PSVersion` |
| CodeRabbit CLI | optional | `tools/cr_full_review.sh` | `coderabbit --version` |
| Codex CLI | optional, 0.162.1 (wrapper 2.6.1, model gpt-6.1-sol) | second reviewer via `tools/codex_ro.py` | `codex --version` |

Expected result: every command answers with a version at or above the minimum. `gh auth status`
lists the scopes `repo` and `security_events` (add missing ones with
`gh auth refresh -s repo,security_events`). Without `security_events` the watch reports
Dependabot/code scanning alerts as "not available"; everything else works.

`requirements.txt` lists no mandatory package. `pip install -r requirements.txt` is optional and
installs nothing; the only optional package (`paramiko`, for the optional secret loader in step 3)
is commented out there.

## 2. Clone

```bash
git clone https://github.com/ujconsulting/ujc-security-checker.git
cd ujc-security-checker
git config core.autocrlf false
python tools/public_check.py --self-test
```

Expected result: `public_check self-test: OK`; the FINDING lines before it come from the test on
purpose. All files are LF; with `core.autocrlf false` git
does not convert them (the gate reports CR line endings as findings).

## 3. Local configuration: `.env` and secrets

Only needed for the mailbox of the disclosure tools (sending reports by mail, reading answers).

```bash
cp .env.example .env
```

Fill in host, port, encryption (`ssl` = implicit TLS, `tls` = STARTTLS) and user names for
incoming (IMAP) and outgoing (SMTP) mail. `.env` is gitignored. For the passwords there are two
ways:

1. **Environment variables** - set `security_mail_password_in` and `security_mail_password_out`
   (and, if you like, all other `security_mail_*` keys) in the environment. Values that are already
   set take precedence over `.env`; if all keys are set, `.env` is not read at all.
2. **Optional secret loader** - set `UJC_VAULT_ENV` to a Python module `vault_env.py` (or its
   folder) that provides `load_vault_env(path, override=False)`: it reads the `.env` file, resolves
   placeholders such as `${vault:<project>/<key>}` from your secret store and sets the values in
   `os.environ`. The loader is not part of this repository; whether it needs `paramiko` depends on
   your store.

Expected result:

```bash
python tools/disclosures/mail_report.py config
```

prints `OK: configuration complete (IMAP ..., SMTP ...)`. No values are printed.

## 4. Mailbox connection

```bash
python tools/disclosures/mail_report.py --check-connection
```

Expected result: `IMAP: login OK (...), EXAMINE INBOX: <n> messages`, `IMAP: Sent folder: ...`
and `SMTP: EHLO + login OK (...), QUIT - nothing sent`. The mailbox is opened read-only; nothing
is sent. An `ERROR: IMAP: ...` or `ERROR: SMTP: ...` line names the failing side (exit 2).

## 4b. Code hosts (forges) and claudex switches

Only needed for repositories that do not live on github.com (GitHub Enterprise / own GitHub server,
Gitea or Forgejo, GitLab, plain git server) and for the Codex gates. Per code host one block
`forge_<alias>_*` in `.env` - see the section "Code hosts" in `.env.example` (`type`, `url`,
`token` as `${vault:...}` reference, optionally `ca_bundle`, `tls_verify`, `allow_http`, `write`,
`accounts`). Writing is off by default (`write=off`). Check:

```bash
python tools/disclosures/forge.py list              # configured forges, no secrets
python tools/disclosures/forge.py check <alias>     # reachability + login (GET only)
```

The switches for the Codex gates (`disclosure_codex_check`, `claudex_finding_check`,
`claudex_exposure_check`, `claudex_audit_mode`, models and efforts, `claudex_loop_dir`) are in
the "claudex" section of `.env.example`; the effective values print with
`python tools/disclosures/codex_check.py config`. Quarantine clones from any source:
`python tools/quarantine_clone.py <source> <name> --ref <ref>`.

## 5. Sandbox: egress network, proxy, scanner image

One entry point, idempotent (skill [`sandbox-setup`](../.claude/skills/sandbox-setup/README.md)):

```bash
tools/setup.sh --check      # status only, changes nothing; exit 1 until the first full run
tools/setup.sh              # set up or complete (first run: a few minutes, ~1 GB downloads)
tools/setup.sh --rebuild    # recreate the proxy, rebuild the image without cache
tools/setup.sh --remove     # teardown: proxy, network, scanner images, DB volume, state
```

Windows PowerShell: `.\tools\setup.ps1 --check` (finds Git Bash, or set `UJC_BASH`).

Expected result of `tools/setup.sh` and afterwards of `tools/setup.sh --check`: six steps with
`OK` lines and the last line `RESULT: sandbox ready (image ujc-scanner:<date>)`, exit 0. Step 3
runs `tools/egress/check.sh` and must end with `RESULT: all checks passed`; otherwise the script
stops and nothing else starts. Without a LAN target `check.sh` says
`NOTE: no LAN target configured ...` and checks the gateway of the Docker bridge network instead.

Optional local settings (gitignored, lines `UJC_<NAME>=<value>`):

| File | Line | Effect |
|---|---|---|
| `private/egress.conf` | `UJC_EGRESS_LAN_TARGET=<ip>:<port>` | a real service in your LAN for the negative test |
| `private/environment.conf` | `UJC_PROTECTED_PATHS=<path>;<path>` | folders where the scripts never create work directories |
| `private/environment.conf` | `UJC_BASH=<path to bash.exe>` | Git Bash for `setup.ps1` |

`tools/setup.sh --remove` aborts while sandbox containers are attached; it removes only objects by
name and keeps proxy logs and base images.

## 6. Codex skills

The skills live in `.claude/skills/`; Codex CLI finds them under `.agents/skills/`.

```bash
python tools/codex_skills_sync.py          # write the mirror
python tools/codex_skills_sync.py --check  # check only
```

Expected result: `OK: <n> skills, 0 deviations`, exit 0. Skills that git ignores (local-only
skills) are mirrored too but reported as `LOCAL ONLY` and not counted.

Codex itself: start it from the repository root (it loads `AGENTS.md`); reviews only through the
read-only wrapper, e.g. `python tools/codex_ro.py --version`.

## 7. Git hooks (public/private gate)

The gate `tools/public_check.py` runs before every commit (`.githooks/pre-commit`, with `--staged`:
it checks the index, i.e. exactly what would be committed, not the work tree) and before
every push (`.githooks/pre-push`, with `--rev <sha>` for each commit being pushed, taken from the
refs git passes on stdin, plus `--history`: it checks the trees of the pushed commits and all of
history, read through git, so uncommitted or untracked files of the work tree never block a push; files tracked although the commit's own `.gitignore` files exclude them are reported too;
without a usable ref line it checks `HEAD`, never nothing). A carriage return is a finding except
in files whose checkout line ending is CRLF by design (`*.ps1`, `*.bat`, `*.cmd` in
`.gitattributes`; the gate asks `git check-attr`); a BOM is always a finding. Files it cannot inspect (binary other than
common image/font/PDF types, or over 5 MiB) are findings. Activate the hooks for this repository only:

```bash
git config core.hooksPath .githooks
```

Expected result: `git config --get core.hooksPath` prints `.githooks`; the next `git commit`
prints `pre-commit: public/private gate ...` and `TREE: 0 findings (none)`. A finding blocks the
commit (exit 1) and names file, line and check.

**Chaining to your existing hooks.** A local `core.hooksPath` replaces the global one, so the
scripts in `.githooks/` call the hook you had before, with the same arguments and stdin:

1. `UJC_CHAINED_HOOKS_PATH` if set (a folder with your hooks),
2. otherwise the global or system `core.hooksPath` (`git config --global --get core.hooksPath`),
3. otherwise `.git/hooks/<hook>` of this clone.

The previous hook runs only after the gate passed; its exit code becomes the result. If no
previous hook exists, nothing is chained; if one is configured but unusable (not executable, or
its folder cannot be resolved) the hook aborts with an error instead of skipping it. Global
configuration is never changed. On Windows, keep the executable bit when committing hook changes:
`git update-index --chmod=+x .githooks/pre-commit .githooks/pre-push .githooks/_run_gate.sh`.

Manual runs:

```bash
python tools/public_check.py                 # working tree
python tools/public_check.py --staged        # the index, as the pre-commit hook checks it
python tools/public_check.py --rev HEAD      # the tree of a commit, read through git (pre-push)
python tools/public_check.py --history       # plus every commit and commit message
python tools/public_check.py --stamp README_de.md   # refresh the source hash after translating
```

Private lists (gitignored): `private/public_check_denylist.txt` (internal names, one per line, `re:`
for a regular expression; never printed, only "denylist entry #N") and
`private/public_check_allow.txt` (own public repositories that may be named). Both are optional for
the gate. **Before any disclosure the deny list must exist:** the disclosure leak scan reads it and
refuses to run without it. An empty file is a deliberate "none":
`mkdir -p private && touch private/public_check_denylist.txt`.

## 8. Scheduled watch task (Windows, only after the owner's decision)

The daily watch of disclosures, inbox and mailbox is registered only after the owner approved it.

```powershell
.\tools\disclosures\scheduled_task_setup.ps1                                  # dry run, shows what it would do
.\tools\disclosures\scheduled_task_setup.ps1 -Install -Time 08:30 -VaultEnv <path>
.\tools\disclosures\scheduled_task_setup.ps1 -Remove
```

Expected result: the dry run changes nothing; `-Install` registers the task
`UJC-Disclosure-Watch`, which runs `python tools/disclosures/disclosure_watch.py --flag` daily. On
news or errors it creates `private/disclosures/NEW.flag` and shows a balloon; log
`private/disclosures/watch.log`. `-VaultEnv` is only needed for the mailbox (step 3). Manual run:
`python tools/disclosures/disclosure_watch.py` (exit 0 nothing new, 1 news, 2 error). It also reads the
upstream repositories named in `repos/*/README.md` through the GitHub API, which can take several minutes
without output; `--no-repos` limits it to your own repositories.

## 9. Before the repository goes public

In this order (skill [`finding-disclosure`](../.claude/skills/finding-disclosure/README.md),
section "Own public repositories"):

1. Switch on **private vulnerability reporting** (GitHub: Settings -> Advanced Security).
2. Check: `python tools/disclosures/own_repos_check.py` lists the repository with `pvr=on`.
3. Only then rely on [`SECURITY.md`](../SECURITY.md), which points to exactly that channel.
4. Gate over the whole history: `python tools/public_check.py --history` must exit 0.

## 10. Verification checklist

- [ ] `python tools/public_check.py --self-test` -> `public_check self-test: OK`
- [ ] `python tools/public_check.py` -> exit 0 (`TREE: 0 findings`)
- [ ] `python tools/codex_skills_sync.py --check` -> exit 0
- [ ] self-tests of the disclosure tools, each exit 0:
      `python tools/disclosures/leak_scan.py --self-test`,
      `python tools/disclosures/approval.py --self-test`,
      `python tools/disclosures/channel.py --self-test`,
      `python tools/disclosures/advisory_submit.py --self-test`,
      `python tools/disclosures/mail_report.py --self-test`,
      `python tools/disclosures/disclosure_watch.py --self-test`,
      `python tools/codex_skills_sync.py --self-test`
- [ ] `python tools/disclosures/register.py check` -> `0 errors`
- [ ] `tools/setup.sh --check` -> `RESULT: sandbox ready`
- [ ] `gh auth status` -> logged in, scopes `repo`, `security_events`
- [ ] optional: `python tools/disclosures/mail_report.py --check-connection` -> IMAP and SMTP OK
- [ ] `git config --get core.hooksPath` -> `.githooks` (if you activated the hooks)
