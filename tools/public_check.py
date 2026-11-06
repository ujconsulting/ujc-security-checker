#!/usr/bin/env python3
"""Public/private gate: checks everything git would publish before a commit or a push.

This repository is public. The gate refuses what must not go out:

  internal     local Windows/home paths, private IP addresses, internal host names, names
               from the private deny list (private/public_check_denylist.txt), own
               repositories that are not on the allow list (private/public_check_allow.txt)
  ai           AI attribution (co-author trailers, "generated with/written by <AI>" lines);
               naming Claude Code or Codex as a platform or reviewer tool is fine
  german       German text outside files named *_de.md (word-list heuristic plus umlauts)
  pairing      README.md without README_de.md; skill without README.md/README_de.md;
               *_de.md without a source header or with a stale source hash
  embargo      anything under private/ tracked; GHSA ids or K-numbered confidential
               findings in public files unless the register marks them published
  tracked      tracked files that .gitignore excludes (they would still be published)
  format       CR line endings or a UTF-8 BOM
  record       any path below repos/ other than repos/<name>/README.md and
               repos/<name>/README_de.md (reviews, disclosures, policy evidence ... live in the
               gitignored private/records/<name>/; only the summary README is versioned).
               Reported in every mode including --history (old commits count until history is
               rewritten)

Scope: every file of `git ls-files -co --exclude-standard` that exists on disk. With
--staged (pre-commit) the scope is the index instead: every tracked path is read as the
blob that would be committed (`git ls-files -s`, `git cat-file`), untracked files and
unstaged edits do not count, and the pairing/stamp checks hash the staged content as well.
Files with a NUL byte in the first 8 KiB (unless the extension is a known binary type) and
files over 5 MiB cannot be inspected and are findings (fail closed). With --history additionally every blob of every commit (`git rev-list --all` + `git ls-tree -r`)
and every commit message; history findings are reported in a section of their own.
With --rev <commit> (repeatable, pre-push) the scope is the tree of that commit: every blob is
read through git (`git ls-tree -r`, `git cat-file`), the work tree is not read at all (the
register of published findings comes from the commit as well; only the gitignored private
lists are read from disk, they are in no commit). The "tracked although ignored" check uses
the .gitignore files OF THE COMMIT (root and nested): they are written into an empty temporary
repository and the commit's paths are run through `git check-ignore --no-index`; global excludes
and .git/info/exclude do not take part (stricter than --staged, which uses git's own rule set).

Line endings: a CR is a finding, except in files whose checkout line ending is CRLF by design
(`git check-attr eol` says crlf and text is set or auto, e.g. `*.ps1 text eol=crlf` in
.gitattributes). That exemption exists in the work-tree mode only; blobs (index, commits) are
LF by design, so there a CR is always a finding. A BOM is a finding everywhere.

Source header of a translation or derived doc (first lines of the file):

    <!-- source: README.md sha256:<hex> -->

The path is relative to the folder of the file that carries the header. `--stamp <file>`
writes the current hashes into the headers of that file.

    python tools/public_check.py                 # working tree (manual run)
    python tools/public_check.py --staged        # the index, as committed (pre-commit)
    python tools/public_check.py --history       # plus all commits
    python tools/public_check.py --rev HEAD --history   # pushed commits + all commits (pre-push)
    python tools/public_check.py --stamp docs/SETUP_de.md
    python tools/public_check.py --self-test

Exit: 0 clean, 1 findings, 2 error (no git, not a repository, bad arguments).
Output is ASCII only; deny-list hits are shown as "denylist entry #N", never as text.
Standard library + git only.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DENYLIST = "private/public_check_denylist.txt"
ALLOWLIST = "private/public_check_allow.txt"
DEFAULT_ALLOW = ("ujconsulting/claudex-loop", "ujconsulting/ujc-security-checker")
REGISTER = "disclosures/register.json"
MAX_BYTES = 5 * 1024 * 1024
# Binary files are not inspectable; they are findings unless the extension is listed here.
# (The tree tracks none of them today - the list is the explicit decision, not a convenience.)
BINARY_OK_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
                 ".woff", ".woff2", ".ttf", ".otf")

# Record layout: below repos/ only the summary READMEs are versioned.
RECORD_OK = re.compile(r"^repos/[^/]+/README(?:_de)?\.md$")

# Per-file exemptions from whole checks, with the reason.
FILE_EXEMPT = {
    # this file contains the German word list and the AI attribution patterns themselves
    "tools/public_check.py": {"german", "ai"},
    # verbatim copy of the public claudex-loop wrapper (do not edit by hand); its test data
    # contains German sample words
    "tools/codex_ro.py": {"german"},
    # the license text is fixed English legal text without a German counterpart
    "LICENSE": {"german"},
}

# Whitelist of "internal" matches by file and pattern (generic ranges and test fixtures).
_RFC_RANGES = r"(?:0\.0\.0\.0/8|10\.0\.0\.0/8|100\.64\.0\.0/10|127\.0\.0\.0/8|169\.254\.0\.0/16|" \
              r"172\.16\.0\.0/12|192\.0\.0\.0/24|192\.168\.0\.0/16|198\.18\.0\.0/15)"
INTERNAL_WHITELIST = {
    # egress deny rules: they list the private ranges on purpose
    "tools/egress/squid.conf": [_RFC_RANGES],
    ".claude/skills/proxmox-lxc-sandbox/SKILL.md": [_RFC_RANGES],
    # default gateway of Docker's bridge network, used as a generic fallback target
    "tools/egress/check.sh": [r"172\.17\.0\.1"],
    # self-test fixtures of the disclosure leak scanner
    "tools/disclosures/leak_scan.py": [r"192\.168\.1\.10", r"D:\\\\work\\\\x", r"/home/user/x"],
    # placeholder path in the documentation of the wrapper
    "tools/codex_ro.py": [r"Z:\\repo"],  # public-check: allow internal
}

# Justified exceptions in the file itself: one line ("public-check: allow <checks>") or a
# region ("public-check: begin-allow <checks>" ... "public-check: end-allow").
PRAGMA = re.compile(r"public-check:\s*allow\s+([a-z,-]+)")
REGION_BEGIN = re.compile(r"public-check:\s*begin-allow\s+([a-z,-]+)")
REGION_END = re.compile(r"public-check:\s*end-allow")

# ---------------------------------------------------------------------------- patterns

DRIVE_PATH = re.compile(r"(?<![\w/\\])([A-Za-z]):[\\/]+([^\s`'\"<>|*?\\/)\]]*)")
GENERIC_DRIVE_DIRS = {"program", "program files", "program files (x86)", "windows", "programdata", "work", ""}
GITBASH_PATH = re.compile(r"(?:^|(?<=[\s\"'`(=]))/([a-z])/([A-Za-z][\w.-]*)")
HOME_PATH = re.compile(r"(?:^|(?<=[\s\"'`(=:]))(/home/|/Users/)([A-Za-z0-9_.$<{*-][^/\s`'\"):,]*)")
GENERIC_HOMES = {"user", "<user>", "scanner", "runner", "node", "$user", "${user}", "...", "<name>",
                 "out", "sandbox"}
UNC_PATH = re.compile(r"\\\\[A-Za-z0-9_.-]{2,}\\[A-Za-z0-9_$]")
PRIVATE_IP = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?(?![\d.]*\d)")
INTERNAL_HOST = re.compile(
    r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:lan|local|intern|internal|corp|home\.arpa|fritz\.box)"
    r"(?![\w.-])")
GENERIC_HOSTS = {"host.docker.internal"}

_AI = r"(?:claude|anthropic|codex|chat-?gpt|gpt-?\d[\w.-]*|openai|copilot|gemini|an?\s+(?:ai|llm)|ai|llm)"
AI_PATTERNS = [
    re.compile(r"(?i)co-authored-by:[^\n]*(?:claude|anthropic|openai|codex|copilot|gpt|gemini)"),
    re.compile(r"(?i)noreply@anthropic\.com"),
    re.compile(r"(?i)\b(?:generated|written|authored|created|produced|drafted|co-written)\s+"
               r"(?:with|by|using)\s+\[?" + _AI + r"\b"),
    re.compile(r"(?i)\b(?:with the help of|assisted by)\s+\[?" + _AI + r"\b"),
    re.compile("\U0001F916"),
]

GERMAN_CHARS = re.compile("[\u00e4\u00f6\u00fc\u00c4\u00d6\u00dc\u00df]")
# function words: a line needs two different ones
GERMAN_WEAK = """und oder nicht ist sind wird werden wurde auch nur noch schon eine einen einem einer
eines kein keine keinen ohne mit auf bei nach zum zur vom beim dem der das sich wenn
dann dass weil aber sowie hier jetzt alle alles siehe bitte immer wieder zwischen gegen unter durch
als wie wir ich ihr uns diese dieser dieses diesem muss soll sollen kann darf gibt geht steht
liegt gilt""".split()
# distinctive words: one is enough (lower case and capitalised)
GERMAN_STRONG = """datei dateien ordner aufgabe aufgaben freigabe freigaben auftraggeber einsatz
einsatzanalyse meldung meldungen werkzeug werkzeuge hinweis hinweise abschnitt beispiel fehler
ergebnis vorlage vorlagen regel regeln sitzung rechner kunde kunden befund befunde runde umsetzung
pflicht entwurf zusammenfassung bedrohungsmodell nachpruefung endtest einrichtung schritt schritte
netz pruefung pruefen fuer ueber koennen muessen waehrend naechste aenderung aenderungen loeschen
schluessel einreichen meldeweg richtlinie selbsttest trocken quelle titel eltern bereich bereiche
seiten archiv lokal""".split()


def _word_re(words):
    alts = sorted({w for x in words for w in (x, x[:1].upper() + x[1:])}, key=len, reverse=True)
    return re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, alts)) + r")(?![\w-])")


GERMAN_WEAK_RE = _word_re(GERMAN_WEAK)
GERMAN_STRONG_RE = _word_re(GERMAN_STRONG)

# real ids use this alphabet; ids made of one repeated character per group are placeholders
GHSA = re.compile(r"(?i)\bGHSA-([2-9cfghjmpqrvwx]{4})-([2-9cfghjmpqrvwx]{4})-([2-9cfghjmpqrvwx]{4})\b")
K_ID = re.compile(r"\bK(\d{1,3})\b")
SOURCE_HEADER = re.compile(r"<!--\s*source:\s*(\S+)\s+sha256:([0-9a-f]{64}|\S*)\s*-->")
OWN_REPO_TMPL = r"(?i)(?<![\w.-])(?:https?://)?(?:github\.com/)?({owners})/([A-Za-z0-9_.-]+)"


# ---------------------------------------------------------------------------- helpers

def ascii_safe(text: str, limit: int = 90) -> str:
    text = text.replace("\t", " ").strip()
    if len(text) > limit:
        text = text[:limit] + "..."
    return text.encode("ascii", "backslashreplace").decode("ascii")


def out(line: str) -> None:
    sys.stdout.write(ascii_safe(line, 400) + "\n")


class GateError(Exception):
    pass


def git(root: Path, *args: str, binary: bool = False, stdin: bytes | None = None):
    try:
        res = subprocess.run(["git", "-C", str(root), *args], input=stdin,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except FileNotFoundError as exc:
        raise GateError("git not found") from exc
    if res.returncode != 0:
        raise GateError(f"git {' '.join(args[:2])} failed: "
                        f"{res.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return res.stdout if binary else res.stdout.decode("utf-8", "replace")


def matches(path: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def load_lines(path: Path):
    if not path.is_file():
        return None
    return [z.strip() for z in path.read_text(encoding="utf-8").splitlines()
            if z.strip() and not z.lstrip().startswith("#")]


class Context:
    """Lists and register state that the checks need."""

    def __init__(self, root: Path, register_bytes: bytes | None = None, register_from_git: bool = False):
        """register_from_git: take the register from register_bytes (None = absent), not from disk."""
        self.root = root
        deny = load_lines(root / DENYLIST)
        self.deny_missing = deny is None
        self.deny = []
        for entry in deny or []:
            pattern = entry[3:] if entry.startswith("re:") else (
                r"(?<![\w-])" + re.escape(entry) + r"(?![\w-])")
            try:
                self.deny.append(re.compile(pattern, re.I))
            except re.error:
                raise GateError(f"{DENYLIST}: entry #{len(self.deny) + 1} is not a valid pattern")
        allow = load_lines(root / ALLOWLIST)
        self.allow_missing = allow is None
        self.allow = {a.lower().rstrip("/") for a in (allow if allow is not None else DEFAULT_ALLOW)}
        owners = sorted({a.split("/")[0] for a in self.allow if "/" in a})
        self.own_repo = re.compile(OWN_REPO_TMPL.format(owners="|".join(map(re.escape, owners)))) \
            if owners else None
        self.published_ghsa, self.published_k = set(), {}
        reg = root / REGISTER
        if register_from_git:
            reg_raw = register_bytes
        else:
            reg_raw = reg.read_bytes() if reg.is_file() else None
        if reg_raw is not None:
            try:
                entries = json.loads(reg_raw.decode("utf-8"))
            except ValueError as exc:
                raise GateError(f"{REGISTER} is not valid JSON") from exc
            for e in entries if isinstance(entries, list) else []:
                if not e.get("public"):
                    continue
                for field in ("reference", "url"):
                    for m in GHSA.finditer(str(e.get(field) or "")):
                        self.published_ghsa.add(m.group(0).upper())
                draft = str(e.get("draft") or "")
                m = re.match(r"repos/([^/]+)/disclosures/K(\d+)\b", draft)
                if m:
                    self.published_k.setdefault(m.group(1), set()).add(m.group(2))


# ---------------------------------------------------------------------------- content checks

def _whitelisted(path: str, text: str) -> bool:
    for pattern in INTERNAL_WHITELIST.get(path, []):
        if re.fullmatch(pattern, text):
            return True
    return False


def check_internal(path, nr, line, ctx, add):
    for m in DRIVE_PATH.finditer(line):
        first = m.group(2).lower()
        if first in GENERIC_DRIVE_DIRS or first.startswith(("<", "%", "$")) or not first.strip(".") or \
                _whitelisted(path, m.group(0).rstrip("\\/")) or \
                any(_whitelisted(path, x) for x in (line[m.start():m.start() + 12],)):
            continue
        add("internal", nr, f"local Windows path: {m.group(0)}")
    for m in GITBASH_PATH.finditer(line):
        if m.group(2).lower() in ("program", "windows", "tmp"):
            continue
        add("internal", nr, f"local path (Git Bash form): {m.group(0)}")
    for m in HOME_PATH.finditer(line):
        name = m.group(2).lower().rstrip(".,;:")
        if name in GENERIC_HOMES or name.startswith(("<", "$", "{", "*")) or \
                _whitelisted(path, m.group(0)) or _whitelisted(path, line[m.start():m.end() + 2]):
            continue
        add("internal", nr, f"home path: {m.group(0)}")
    for m in UNC_PATH.finditer(line):
        add("internal", nr, f"network share path: {m.group(0)}")
    for m in PRIVATE_IP.finditer(line):
        if _whitelisted(path, m.group(0)):
            continue
        add("internal", nr, f"private IP address: {m.group(0)}")
    for m in INTERNAL_HOST.finditer(line):
        if m.group(0).lower() in GENERIC_HOSTS:
            continue
        add("internal", nr, f"internal host name: {m.group(0)}")
    for i, rx in enumerate(ctx.deny, 1):
        if rx.search(line):
            add("internal", nr, f"denylist entry #{i}", secret=True)
    if ctx.own_repo:
        for m in ctx.own_repo.finditer(line):
            name = re.sub(r"(\.git)?[.,;:]*$", "", m.group(2))
            if not name or f"{m.group(1)}/{name}".lower() in ctx.allow:
                continue
            add("internal", nr, f"own repository not on the allow list: {m.group(1)}/{name}")


def check_ai(nr, line, add):
    for rx in AI_PATTERNS:
        m = rx.search(line)
        if m:
            add("ai", nr, f"AI attribution: {m.group(0)}")
            return


def german_hit(line: str):
    m = GERMAN_CHARS.search(line)
    if m:
        return f"umlaut or sharp s: {line[max(0, m.start() - 20):m.end() + 20]}"
    m = GERMAN_STRONG_RE.search(line)
    if m:
        return f"German word '{m.group(1)}'"
    weak = {w.lower() for w in GERMAN_WEAK_RE.findall(line)}
    if len(weak) >= 2:
        return "German words " + ", ".join(sorted(weak)[:4])
    return None


def check_embargo(path, nr, line, ctx, add):
    for m in GHSA.finditer(line):
        if all(len(set(g.lower())) == 1 for g in m.groups()):
            continue
        if m.group(0).upper() not in ctx.published_ghsa:
            add("embargo", nr, f"advisory id not marked published in the register: {m.group(0)}")
    record = path.split("/")[1] if path.startswith("repos/") and path.count("/") >= 2 else None
    allowed = ctx.published_k.get(record, set()) if record else \
        set().union(*ctx.published_k.values()) if ctx.published_k else set()
    for m in K_ID.finditer(line):
        if m.group(1) not in allowed:
            add("embargo", nr, f"K-numbered confidential finding: {m.group(0)}")


def scan_content(path: str, data: bytes, ctx: Context, findings: list, exempt_files=FILE_EXEMPT,
                 crlf_ok: bool = False):
    """Content checks of one file; appends (check, path, line, message, secret).

    crlf_ok: the checkout line ending of this file is CRLF by design (see crlf_by_attr)."""
    def add(check, nr, msg, secret=False):
        if check in skip or check in pragmas.get(nr, set()):
            return
        findings.append((check, path, nr, msg, secret))

    skip = set(exempt_files.get(path, set()))
    pragmas: dict = {}
    if path.startswith("repos/") and not RECORD_OK.match(path):
        findings.append(("record", path, 0, "only repos/<name>/README.md and README_de.md are versioned "
                         "(details belong in private/records/<name>/)", False))
    if len(data) > MAX_BYTES:
        findings.append(("format", path, 0, "not inspectable (too large)", False))
        return
    if b"\0" in data[:8192]:
        if not path.lower().endswith(BINARY_OK_EXT):
            findings.append(("format", path, 0, "not inspectable (binary)", False))
        return
    if data.startswith(b"\xef\xbb\xbf"):
        findings.append(("format", path, 1, "UTF-8 BOM", False))
    if b"\r" in data and not crlf_ok:
        findings.append(("format", path, data[:data.index(b"\r")].count(b"\n") + 1,
                         "CR line ending", False))
    text = data.decode("utf-8", "replace")
    name = path.rsplit("/", 1)[-1]
    is_de = name.endswith("_de.md")
    is_md = name.endswith(".md")
    if is_de or path.startswith("private/"):
        skip.add("german")
    in_fence = False
    region: set = set()
    for nr, line in enumerate(text.splitlines(), 1):
        b = REGION_BEGIN.search(line)
        if b:
            region = set(b.group(1).split(","))
        if REGION_END.search(line):
            region = set()
        p = PRAGMA.search(line)
        if p or region:
            pragmas[nr] = set(p.group(1).split(",")) if p else set()
            pragmas[nr] |= region
        if is_md and line.lstrip().startswith("```"):
            in_fence = not in_fence
        check_internal(path, nr, line, ctx, add)
        check_ai(nr, line, add)
        check_embargo(path, nr, line, ctx, add)
        german_line = True
        if is_md and line.lstrip().startswith(">"):
            german_line = False          # quoted upstream text
        if name == ".env.example" and re.match(r"\s*[A-Za-z_][\w]*=", line):
            german_line = False          # placeholder values
        if german_line:
            hit = german_hit(line)
            if hit:
                add("german", nr, hit)


# ---------------------------------------------------------------------------- tree checks

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_headers(text: str):
    return [(m.group(1), m.group(2)) for m in SOURCE_HEADER.finditer("\n".join(text.splitlines()[:8]))]


def check_pairing(root: Path, files: list, findings: list, reader=None):
    """reader(path) -> bytes or None; default: the work tree. The staged mode passes the index."""
    published = set(files)
    if reader is None:
        def reader(rel):
            try:
                return (root / rel).read_bytes()
            except OSError:
                return None

    def add(path, msg):
        findings.append(("pairing", path, 0, msg, False))

    for f in files:
        name = f.rsplit("/", 1)[-1]
        folder = f.rsplit("/", 1)[0] + "/" if "/" in f else ""
        if name == "README.md" and folder + "README_de.md" not in published:
            add(f, f"missing German counterpart {folder}README_de.md")
        if fnmatch.fnmatchcase(f, ".claude/skills/*/SKILL.md"):
            for doc in ("README.md", "README_de.md"):
                if folder + doc not in published:
                    add(f, f"skill without {folder}{doc}")
        if not f.endswith(".md"):
            continue
        raw = reader(f)
        if raw is None:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        headers = source_headers(text)
        if name.endswith("_de.md") and not headers:
            add(f, "German file without a source header <!-- source: <file> sha256:<hash> -->")
        for src, digest in headers:
            target = (root / folder / src).resolve()
            try:
                rel = target.relative_to(root.resolve()).as_posix()
            except ValueError:
                add(f, f"source {src} lies outside the repository")
                continue
            src_data = reader(rel) if rel in published else None
            if src_data is None:
                add(f, f"source {src} is missing or not published")
            elif hashlib.sha256(src_data).hexdigest() != digest:
                add(f, f"stale: source {src} changed since the translation (run --stamp after updating)")


def published_files(root: Path):
    listed = git(root, "ls-files", "-co", "--exclude-standard", "-z").split("\0")
    return sorted({f for f in listed if f and (root / f).is_file()})


def staged_blobs(root: Path):
    """{path: blob sha} of the index; submodule entries (mode 160000) are not files."""
    blobs = {}
    for entry in git(root, "ls-files", "-s", "-z").split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[0] != "160000" and parts[2] == "0":
            blobs[path] = parts[1]
    return blobs


def crlf_by_attr(root: Path, files: list) -> set:
    """Paths whose checkout line ending is CRLF by design, asked of git itself (one call):
    eol=crlf from .gitattributes, with text set or auto. An error raises (fail closed)."""
    if not files:
        return set()
    stdin = "".join(f + "\0" for f in files).encode("utf-8")
    raw = git(root, "check-attr", "--stdin", "-z", "eol", "text", binary=True, stdin=stdin)
    parts = raw.decode("utf-8", "replace").split("\0")
    attrs: dict = {}
    for i in range(0, len(parts) - 2, 3):
        attrs[(parts[i], parts[i + 1])] = parts[i + 2]
    return {f for f in files
            if attrs.get((f, "eol")) == "crlf" and attrs.get((f, "text")) in ("set", "auto")}


def check_tree(root: Path, ctx: Context, staged: bool = False):
    findings = []
    if staged:
        blobs = staged_blobs(root)
        files = sorted(blobs)
        cache: dict = {}

        def reader(rel):
            if rel not in blobs:
                return None
            if rel not in cache:
                cache[rel] = git(root, "cat-file", "blob", blobs[rel], binary=True)
            return cache[rel]
    else:
        files = published_files(root)
        reader = None
    crlf = set() if staged else crlf_by_attr(root, files)
    for f in files:
        data = reader(f) if staged else (root / f).read_bytes()
        scan_content(f, data, ctx, findings, crlf_ok=f in crlf)
    tracked_private = [f for f in git(root, "ls-files", "-c", "-z", "--", "private").split("\0") if f]
    for f in tracked_private:
        findings.append(("embargo", f, 0, "file under private/ is tracked (git rm --cached)", False))
    ignored = [f for f in git(root, "ls-files", "-ci", "--exclude-standard", "-z").split("\0")
               if f and (staged or (root / f).exists()) and not f.startswith("private/")]
    for f in ignored:
        findings.append(("tracked", f, 0, "tracked although .gitignore excludes it (git rm --cached)", False))
    check_pairing(root, files, findings, reader)
    return files, findings


# ---------------------------------------------------------------------------- pushed commits

def rev_blobs(root: Path, rev: str):
    """{path: blob sha} of the tree of one commit; submodules (type commit) are not files."""
    blobs = {}
    for entry in git(root, "ls-tree", "-r", "-z", rev).split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob":
            blobs[path] = parts[2]
    return blobs


def ignored_by_commit_rules(paths: list, gitignores: dict) -> list:
    """Paths that the .gitignore files of a commit exclude. gitignores: {path: bytes}. Evaluated
    in an empty temporary repository with no global excludes and no info/exclude; exit 128 or
    any other error raises (fail closed)."""
    if not paths or not gitignores:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        tdir = Path(tmp)
        git(tdir, "init", "-q", "--template=")
        for rel, data in gitignores.items():
            target = tdir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        stdin = "".join(f + "\0" for f in paths).encode("utf-8")
        res = subprocess.run(["git", "-C", str(tdir), "-c", f"core.excludesFile={os.devnull}",
                              "check-ignore", "--no-index", "--stdin", "-z"],
                             input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if res.returncode not in (0, 1):
            raise GateError("git check-ignore failed: "
                            + res.stderr.decode("utf-8", "replace").strip()[:200])
        return [x for x in res.stdout.decode("utf-8", "replace").split("\0") if x]


def check_revs(root: Path, revs: list):
    """Tree checks over the trees of the given commits, read through git only (pre-push).

    Same checks as the tree mode (internal, ai, german, embargo, format, private/, pairing and
    stamps, tracked although ignored by the commit's own .gitignore files). Returns (files, findings);
    with more than one rev the finding paths carry the short commit id."""
    findings = []
    seen_files = 0
    cache: dict = {}
    for rev in revs:
        commit = git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}").strip()
        if not commit:
            raise GateError(f"{rev} is not a commit")
        blobs = rev_blobs(root, commit)
        files = sorted(blobs)
        seen_files += len(files)
        reg = blobs.get(REGISTER)
        ctx = Context(root, git(root, "cat-file", "blob", reg, binary=True) if reg else None,
                      register_from_git=True)

        def label(p, c=commit):
            return f"{c[:7]}:{p}" if len(revs) > 1 else p

        def reader(rel, blobs=blobs):
            if rel not in blobs:
                return None
            if blobs[rel] not in cache:
                cache[blobs[rel]] = git(root, "cat-file", "blob", blobs[rel], binary=True)
            return cache[blobs[rel]]

        local: list = []
        for f in files:
            scan_content(f, reader(f), ctx, local)
        check_pairing(root, files, local, reader)
        for f in files:
            if f.startswith("private/"):
                local.append(("embargo", f, 0, "file under private/ is tracked (git rm --cached)", False))
        gitignores = {f: reader(f) for f in files if f.rsplit("/", 1)[-1] == ".gitignore"}
        for f in ignored_by_commit_rules(files, gitignores):
            if not f.startswith("private/"):
                local.append(("tracked", f, 0,
                              "tracked although .gitignore excludes it (git rm --cached)", False))
        findings += [(c, label(p), n, m, s) for (c, p, n, m, s) in local]
    return seen_files, findings


# ---------------------------------------------------------------------------- history

def check_history(root: Path, ctx: Context):
    findings = []
    commits = [c for c in git(root, "rev-list", "--all").split() if c]
    blobs: dict = {}
    for c in commits:
        for entry in git(root, "ls-tree", "-r", "-z", c).split("\0"):
            if not entry:
                continue
            meta, _, path = entry.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                blobs.setdefault((parts[2], path), c[:7])
                if path.startswith("private/"):
                    findings.append(("embargo", f"{c[:7]}:{path}", 0, "file under private/ in history", False))
    # keyed on (blob, path): the same content under another path is checked again, because
    # language, embargo and exemptions depend on the path
    for (sha, path), commit in sorted(blobs.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        data = git(root, "cat-file", "blob", sha, binary=True)
        before = len(findings)
        scan_content(path, data, ctx, findings)
        for i in range(before, len(findings)):
            check, p, nr, msg, secret = findings[i]
            findings[i] = (check, f"{commit}:{p}", nr, msg, secret)
    log = git(root, "log", "--all", "--format=%H%x00%B%x01")
    for record in log.split("\x01"):
        sha, _, body = record.strip("\n").partition("\0")
        for nr, line in enumerate(body.splitlines(), 1):
            def add(check, n, msg, secret=False, _sha=sha):
                findings.append((check, f"{_sha[:7]}:<commit message>", n, msg, secret))
            check_ai(nr, line, add)
            check_internal("<commit message>", nr, line, ctx, add)
    return len(commits), len(blobs), findings


# ---------------------------------------------------------------------------- report

def report(title: str, findings: list) -> int:
    seen = set()
    counts: dict = {}
    for check, path, nr, msg, _secret in findings:
        key = (check, path, nr, msg)
        if key in seen:
            continue
        seen.add(key)
        counts[check] = counts.get(check, 0) + 1
        where = f"{path}:{nr}" if nr else path
        out(f"FINDING [{check}] {where}: {msg}")
    total = sum(counts.values())
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"
    out(f"{title}: {total} findings ({summary})")
    return total


def stamp(root: Path, files) -> int:
    for f in files:
        path = (root / f) if not Path(f).is_absolute() else Path(f)
        if not path.is_file():
            out(f"ERROR: {f} not found")
            return 2
        text = path.read_text(encoding="utf-8")
        headers = source_headers(text)
        if not headers:
            out(f"ERROR: {f} has no source header")
            return 2
        for src, _old in headers:
            target = path.parent / src
            if not target.is_file():
                out(f"ERROR: {f}: source {src} not found")
                return 2
            new = sha256_file(target)
            text = re.sub(r"(<!--\s*source:\s*" + re.escape(src) + r"\s+sha256:)\S*(\s*-->)",
                          lambda m, n=new: m.group(1) + n + m.group(2), text, count=1)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        out(f"OK: stamped {f}")
    return 0


def run(root: Path, history: bool, staged: bool = False, revs: list | None = None) -> int:
    ctx = Context(root)
    if ctx.deny_missing:
        out(f"NOTE: {DENYLIST} not present - deny list not checked")
    if ctx.allow_missing:
        out(f"NOTE: {ALLOWLIST} not present - built-in allow list used")
    if revs:
        nfiles, findings = check_revs(root, revs)
        out(f"commits {', '.join(revs)}: {nfiles} files checked")
    else:
        files, findings = check_tree(root, ctx, staged)
        nfiles = len(files)
        out(f"{'index' if staged else 'tree'}: {nfiles} files checked")
    total = report("TREE", findings)
    if history:
        commits, blobs, hist = check_history(root, ctx)
        out(f"history: {commits} commits, {blobs} blobs checked")
        total += report("HISTORY", hist)
    return 1 if total else 0


# ---------------------------------------------------------------------------- self-test

def self_test() -> int:
    if not shutil.which("git"):
        out("ERROR: git not found")
        return 2
    bad = []

    def expect(name, cond):
        if not cond:
            bad.append(name)
            out(f"ERROR: self-test case failed: {name}")

    uml = "\u00fc"
    trailer = "Co-" + "Authored-By: " + "Cla" + "ude <x@example.org>"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
        os.environ.update(env)
        git(root, "init", "-q")

        def write(rel, text):
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)

        write(".gitignore", "/private/\n")
        write("private/public_check_denylist.txt", "# internal\nsecret-host-7\nre:\\bproj-[a-z]+\\b\n")
        write("private/public_check_allow.txt", "acme/public-tool\n")
        write("README.md", "# Demo\n\nPlain English text about the tool.\n")
        write("README_de.md", "<!-- source: README.md sha256:0 -->\n# Demo\n\nDeutscher Text f"
              + uml + "r alle.\n")
        stamp(root, ["README_de.md"])
        write("src/clean.py", "print('hello world')\n")
        ctx = Context(root)
        _, f = check_tree(root, ctx)
        expect("clean tree", not f)

        # fixtures are assembled so that this file itself stays clean for the gate
        ghsa, kid = "GHSA-" + "2c3f-4g5h-6j7m", "K" + "3"
        cases = [
            ("internal", "see C:" + "\\Users\\alice\\work for details\n"),
            ("internal", "mount /home" + "/alice/projects here\n"),
            ("internal", "target 192.168" + ".1.20:3000\n"),
            ("internal", "host nas" + ".lan is used\n"),
            ("internal", "runs on secret-host-7 today\n"),
            ("internal", "like proj-alpha does\n"),
            ("internal", "clone acme/private-tool first\n"),
            ("ai", trailer + "\n"),
            ("ai", "This file was generated with " + "Cha" + "tGPT.\n"),
            ("german", "Diese Datei ist wichtig und nicht leer.\n"),
            ("german", "Der Auftraggeber entscheidet.\n"),
            ("german", "Gr" + "\u00f6\u00df" + "e\n"),
            ("embargo", f"see {ghsa}\n"),
            ("embargo", f"finding {kid} is open\n"),
            ("format", "line\r\n"),
        ]
        for check, text in cases:
            findings = []
            scan_content("docs/x.md", text.encode("utf-8"), ctx, findings)
            expect(f"fires {check}: {text.strip()[:30]}", any(x[0] == check for x in findings))
        quiet = [
            "Claude Code and Codex are the platforms; Codex reviews read-only.\n",
            "acme/public-tool is public, see github.com/acme/public-tool.\n",
            "Docker reaches host.docker.internal; loopback 127.0.0.1 is fine.\n",
            "Install into C:\\Program Files\\Git or ~/.claude/skills/<name>.\n",
            "The MIT license; die() in PHP; the den of the fox.\n",
            "> Bitte keine oeffentlichen Issues (quoted upstream text)\n",
            "read private/CLAUDE.local.md and watch_config.local.json\n",
            "K8s and the GHSA format are explained here.\n",
            "placeholders GHSA-xxxx-xxxx-xxxx and GHSA-pppp-qqqq-rrrr\n",
            "the path X:/... and /home/scanner:rw stay generic\n",
            "Deutsch nur hier. <!-- public-check: allow german -->\n",
            "<!-- public-check: begin-allow german -->\nDiese Datei ist nicht leer.\n"
            "<!-- public-check: end-allow -->\nEnglish again.\n",
        ]
        for text in quiet:
            findings = []
            scan_content("docs/x.md", text.encode("utf-8"), ctx, findings)
            expect(f"silent: {text.strip()[:40]}", not findings)
        findings = []
        scan_content("docs/x_de.md", "Deutscher Text und mehr.\n".encode("utf-8"), ctx, findings)
        expect("German allowed in *_de.md", not findings)
        # record layout: only the summary READMEs below repos/ (both directions)
        for rel in ("repos/a/reviews/x.md", "repos/a/disclosures/x.md", "repos/a/disclosures/policy/S.md",
                    "repos/a/notes.txt"):
            findings = []
            scan_content(rel, b"# x", ctx, findings)
            expect(f"record fires: {rel}", any(x[0] == "record" for x in findings))
        for rel in ("repos/a/README.md", "repos/a/README_de.md", "docs/x.md", "tools/repos/x.md"):
            findings = []
            scan_content(rel, b"# x", ctx, findings)
            expect(f"record silent: {rel}", not any(x[0] == "record" for x in findings))

        # pairing and staleness
        write("tools/README.md", "# Tools\n")
        _, f = check_tree(root, Context(root))
        expect("missing README_de", any(x[0] == "pairing" and "README_de" in x[3] for x in f))
        write("tools/README_de.md", "<!-- source: README.md sha256:0 -->\n# Werkzeuge\n")
        stamp(root, ["tools/README_de.md"])
        write(".claude/skills/demo/SKILL.md", "---\nname: demo\n---\n# demo\n")
        _, f = check_tree(root, Context(root))
        expect("skill without docs", sum(1 for x in f if x[0] == "pairing" and "skill" in x[3]) == 2)
        write(".claude/skills/demo/README.md", "<!-- source: SKILL.md sha256:0 -->\n# demo\n")
        write(".claude/skills/demo/README_de.md", "<!-- source: README.md sha256:0 -->\n# demo\n")
        stamp(root, [".claude/skills/demo/README.md", ".claude/skills/demo/README_de.md"])
        _, f = check_tree(root, Context(root))
        expect("pairing complete", not f)
        write("tools/README.md", "# Tools\n\nChanged.\n")
        _, f = check_tree(root, Context(root))
        expect("stale German file", any("stale" in x[3] for x in f))
        stamp(root, ["tools/README_de.md"])

        # tracked private file, tracked ignored file, history
        git(root, "add", "--", "README.md", "README_de.md", "src/clean.py", ".gitignore",
            "tools", ".claude")
        git(root, "add", "-f", "--", "private/public_check_allow.txt")
        git(root, "commit", "-q", "-m", "first\n\n" + trailer)
        _, f = check_tree(root, Context(root))
        expect("tracked private file", any(x[0] == "embargo" and "private/" in x[1] for x in f))
        git(root, "rm", "-q", "--cached", "--", "private/public_check_allow.txt")
        write("old.md", "Diese Datei ist nicht englisch und alt.\n")
        git(root, "add", "--", "old.md")
        git(root, "commit", "-q", "-m", "second")
        git(root, "rm", "-q", "--", "old.md")
        git(root, "commit", "-q", "-m", "third")
        _, f = check_tree(root, Context(root))
        expect("tree clean after cleanup", not f)
        _, _, h = check_history(root, Context(root))
        expect("history: deleted German file", any(x[0] == "german" and "old.md" in x[1] for x in h))
        expect("history: private file", any(x[0] == "embargo" and "private/" in x[1] for x in h))
        expect("history: AI trailer in message", any(x[0] == "ai" and "commit message" in x[1] for x in h))
        expect("run exit 1 with history", run(root, True) == 1)
        expect("run exit 0 tree only", run(root, False) == 0)

        # fail closed: binary and oversized files
        findings = []
        scan_content("assets/blob.bin", b"ab\0cd", ctx, findings)
        expect("binary is a finding", any("binary" in x[3] for x in findings))
        findings = []
        scan_content("assets/logo.png", b"\x89PNG\0\0", ctx, findings)
        expect("known image type allowed", not findings)
        findings = []
        scan_content("assets/big.txt", b"a" * (MAX_BYTES + 1), ctx, findings)
        expect("too large is a finding", any("too large" in x[3] for x in findings))

        # history: same content under another path is checked on its own path
        same = "Diese Datei ist nicht englisch und neu.\n"
        write("docs/same_de.md", same)
        write("docs/same.md", same)
        git(root, "add", "--", "docs/same_de.md", "docs/same.md")
        git(root, "commit", "-q", "-m", "same content twice")
        _, _, h = check_history(root, Context(root))
        expect("history: dedupe keeps path", any(x[0] == "german" and "same.md" in x[1] for x in h))
        git(root, "rm", "-q", "--", "docs/same_de.md", "docs/same.md")
        git(root, "commit", "-q", "-m", "remove same")

        # staged mode reads the index, not the work tree
        write("docs/staged.md", "Diese Datei ist nicht englisch.\n")
        git(root, "add", "--", "docs/staged.md")
        write("docs/staged.md", "English only now.\n")
        _, f = check_tree(root, Context(root), staged=True)
        expect("staged: finds staged content", any(x[0] == "german" and "staged.md" in x[1] for x in f))
        _, f = check_tree(root, Context(root))
        expect("work tree: sees the clean edit", not any("staged.md" in x[1] for x in f))
        write("untracked_de.md", "Deutsch und mehr.\n")
        _, f = check_tree(root, Context(root), staged=True)
        expect("staged: untracked file ignored", not any("untracked_de" in x[1] for x in f))
        (root / "untracked_de.md").unlink()
        git(root, "rm", "-q", "-f", "--", "docs/staged.md")
        _, f = check_tree(root, Context(root), staged=True)
        expect("staged: deleted entry skipped", not f)
        write("tools/README.md", "# Tools\n\nChanged again.\n")
        git(root, "add", "--", "tools/README.md")
        _, f = check_tree(root, Context(root), staged=True)
        expect("staged: stale pairing on staged content", any("stale" in x[3] for x in f))
        git(root, "reset", "-q", "--", "tools/README.md")
        write("tools/README.md", "# Tools\n\nChanged.\n")

        # embargo lifted by the register
        write("disclosures/register.json", json.dumps([{
            "id": "x-01", "public": True, "reference": ghsa,
            "url": "", "draft": f"repos/a/disclosures/{kid}-advisory.md"}]))
        ctx = Context(root)
        findings = []
        scan_content("repos/a/README.md", f"{ghsa} and {kid} are published\n".encode(), ctx, findings)
        expect("published advisory allowed", not findings)
        findings = []
        scan_content("repos/b/README.md", f"{kid} of another record\n".encode(), ctx, findings)
        expect("K id of another record still blocked", any(x[0] == "embargo" for x in findings))

        # deny-list text never printed
        import io
        buf, old = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            report("T", [("internal", "a.md", 1, "denylist entry #1", True)])
        finally:
            sys.stdout = old
        expect("deny list not printed", "secret-host" not in buf.getvalue())
    gate_mode_tests(Path(__file__).resolve(), expect)
    hook_tests(Path(__file__).resolve(), expect)
    out(f"public_check self-test: {'OK' if not bad else f'{len(bad)} FAILED'}")
    return 1 if bad else 0


def _mk_repo(base: Path, name: str) -> Path:
    root = base / name
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "core.autocrlf", "false")
    git(root, "config", "user.name", "t")
    git(root, "config", "user.email", "t@example.org")
    return root


def _put(root: Path, rel: str, data):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


def _gate(script: Path, root: Path, *args: str):
    """Runs a gate script (CLI) against a repository: (exit code, stdout text)."""
    res = subprocess.run([sys.executable, str(script), "--root", str(root), *args],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return res.returncode, res.stdout.decode("utf-8", "replace")


def _paired_readme(root: Path, english: str):
    """README.md plus a README_de.md whose stamp matches the English text."""
    _put(root, "README.md", english)
    _put(root, "README_de.md", "<!-- source: README.md sha256:"
         + hashlib.sha256(english.encode("utf-8")).hexdigest() + " -->\n# Demo\n")


def gate_mode_tests(script: Path, expect) -> None:
    """CLI-level cases for the CRLF-by-design exemption and the --rev mode. They drive `script`,
    so they can be run against an older copy of this file to show they fail there."""
    de_line = "Diese Datei ist nicht leer.\n"
    ip_line = "target 10.1" + ".2.3 here\n"
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        # -- line endings by .gitattributes
        root = _mk_repo(base, "eol")
        _put(root, ".gitattributes", "* text=auto eol=lf\n*.ps1 text eol=crlf\n")
        _put(root, "a.ps1", b"Write-Output 'hi'\r\n")
        _put(root, "bom.ps1", b"\xef\xbb\xbfWrite-Output 'hi'\r\n")
        _put(root, "b.py", b"x = 1\r\n")
        _put(root, "docs/c.md", b"# T\r\n")
        _put(root, "d.sh", b"echo hi\r\n")
        rc, text = _gate(script, root)
        expect("eol: ps1 with CRLF by attribute is no finding", "a.ps1" not in text)
        expect("eol: BOM in a CRLF ps1 is still a finding", "[format] bom.ps1:1: UTF-8 BOM" in text)
        expect("eol: CRLF in the BOM ps1 is not a finding", "bom.ps1:1: CR line" not in text)
        expect("eol: CRLF in .py is a finding", "[format] b.py:1: CR line ending" in text)
        expect("eol: CRLF in .md is a finding", "[format] docs/c.md:1: CR line ending" in text)
        expect("eol: CRLF in .sh is a finding", "[format] d.sh:1: CR line ending" in text)
        _put(root, ".gitattributes", "* text=auto eol=lf\n")
        rc, text = _gate(script, root)
        expect("eol: without the attribute a ps1 CR is a finding", "[format] a.ps1:1: CR line ending" in text)
        _put(root, ".gitattributes", "* text=auto eol=lf\n*.ps1 eol=crlf -text\n")
        rc, text = _gate(script, root)
        expect("eol: eol=crlf with text unset is no exemption", "[format] a.ps1:1: CR line ending" in text)
        # blobs are LF: staged content is judged as before (a CR in the index is a finding)
        _put(root, ".gitattributes", "* text=auto eol=lf\n*.ps1 text eol=crlf\n")
        git(root, "add", "--", ".gitattributes", "a.ps1")
        rc, text = _gate(script, root, "--staged")
        expect("eol: staged ps1 (LF blob) is clean", "a.ps1" not in text)

        # -- --rev reads commits, not the work tree
        root = _mk_repo(base, "rev")
        _put(root, ".gitignore", "/private/\n")
        _paired_readme(root, "# Demo\n\nPlain English text.\n")
        _put(root, "src/clean.py", "print('hello world')\n")
        git(root, "add", "--", ".gitignore", "README.md", "README_de.md", "src/clean.py")
        git(root, "commit", "-q", "-m", "clean")
        c1 = git(root, "rev-parse", "HEAD").strip()
        _put(root, "dirty.md", de_line)
        _put(root, "ip.txt", ip_line)
        _put(root, "src/clean.py", "print('x')  # " + ip_line)
        rc, text = _gate(script, root, "--rev", "HEAD")
        expect("rev: clean commit passes despite a dirty work tree", rc == 0 and "0 findings" in text)
        rc, text = _gate(script, root)
        expect("tree: the same work tree is reported", rc == 1 and "dirty.md" in text and "ip.txt" in text)
        (root / "dirty.md").unlink()
        (root / "ip.txt").unlink()
        _put(root, "src/clean.py", "print('hello world')\n")
        _put(root, "docs/bad.md", de_line)
        git(root, "add", "--", "docs/bad.md")
        git(root, "commit", "-q", "-m", "bad")
        c2 = git(root, "rev-parse", "HEAD").strip()
        rc, text = _gate(script, root, "--rev", "HEAD")
        expect("rev: committed German text is reported", rc == 1 and "[german] docs/bad.md" in text)
        rc, text = _gate(script, root, "--rev", c1)
        expect("rev: the older clean commit still passes", rc == 0)
        rc, text = _gate(script, root, "--rev", c1, "--rev", c2)
        expect("rev: several revs, finding path carries the commit",
               rc == 1 and f"{c2[:7]}:docs/bad.md" in text)
        _put(root, "private/x.txt", "x\n")
        git(root, "add", "-f", "--", "private/x.txt")
        git(root, "commit", "-q", "-m", "private")
        rc, text = _gate(script, root, "--rev", "HEAD")
        expect("rev: tracked private/ file is reported", "[embargo] private/x.txt" in text)
        git(root, "rm", "-q", "-f", "--", "private/x.txt", "docs/bad.md")
        _put(root, "README.md", "# Demo\n\nChanged English text.\n")
        git(root, "add", "--", "README.md")
        git(root, "commit", "-q", "-m", "readme without restamp")
        _paired_readme(root, "# Demo\n\nChanged English text.\n")      # restamped, not committed
        rc, text = _gate(script, root, "--rev", "HEAD")
        expect("rev: stale stamp in the commit is a pairing finding",
               "[pairing] README_de.md: stale" in text)
        rc, text = _gate(script, root)
        expect("tree: the uncommitted restamp makes the work tree clean", rc == 0)
        git(root, "add", "--", "README_de.md")
        git(root, "commit", "-q", "-m", "restamp")
        rc, text = _gate(script, root, "--rev", "HEAD")
        expect("rev: restamped commit is clean", rc == 0)
        _put(root, "docs/adv.md", "see GHSA-" + "2c3f-4g5h-6j7m\n")
        git(root, "add", "--", "docs/adv.md")
        git(root, "commit", "-q", "-m", "advisory")
        _put(root, "disclosures/register.json", json.dumps([{
            "id": "x", "public": True, "reference": "GHSA-" + "2c3f-4g5h-6j7m", "url": "", "draft": ""}]))
        rc, text = _gate(script, root, "--rev", "HEAD")
        expect("rev: the register of the commit counts, not the work tree", "[embargo] docs/adv.md" in text)
        rc, text = _gate(script, root)
        expect("tree: the work-tree register lifts it", "docs/adv.md" not in text)
        # tracked although ignored, rules taken from the commit
        root2 = _mk_repo(base, "ign")
        _put(root2, ".gitignore", ".env\n*.log\n!keep.log\n")
        _put(root2, "sub/.gitignore", "x.log\n!y.log\n")
        _put(root2, "keep.log", "k\n")
        _put(root2, "other/z.log", "z\n")
        _put(root2, "sub/y.log", "y\n")
        git(root2, "add", "--", ".gitignore", "sub/.gitignore", "keep.log", "sub/y.log")
        git(root2, "add", "-f", "--", "other/z.log")
        git(root2, "commit", "-q", "-m", "ignore rules")
        rc, text = _gate(script, root2, "--rev", "HEAD")
        expect("rev: ignored file in the commit is reported", "[tracked] other/z.log" in text)
        expect("rev: negation !keep.log is not reported", "keep.log" not in text)
        expect("rev: nested negation sub/y.log is not reported", "y.log" not in text)
        git(root2, "rm", "-q", "-f", "--", "other/z.log")
        _put(root2, "sub/x.log", "x\n")
        _put(root2, ".env", "A=1\n")
        git(root2, "add", "-f", "--", "sub/x.log", ".env")
        git(root2, "commit", "-q", "-m", "more ignored")
        rc, text = _gate(script, root2, "--rev", "HEAD")
        expect("rev: .env listed in .gitignore is reported", "[tracked] .env" in text)
        expect("rev: nested sub/.gitignore is honoured", "[tracked] sub/x.log" in text)
        git(root2, "rm", "-q", "-f", "--", "sub/x.log", ".env")
        git(root2, "commit", "-q", "-m", "clean")
        rc, text = _gate(script, root2, "--rev", "HEAD")
        expect("rev: clean commit has no tracked finding", rc == 0 and "tracked" not in text)
        rc, _ = _gate(script, root, "--rev", "0123456789abcdef0123456789abcdef01234567")
        expect("rev: unknown commit is exit 2", rc == 2)
        rc, _ = _gate(script, root, "--rev", "HEAD", "--staged")
        expect("rev: combined with --staged is exit 2", rc == 2)


def hook_tests(script: Path, expect) -> None:
    """Runs the real pre-push hook in a temp repository (stdin line in, exit code out)."""
    hooks = script.parent.parent / ".githooks"
    sh = shutil.which("sh")
    if not sh or not (hooks / "pre-push").is_file():
        out("NOTE: hook self-test skipped (sh or .githooks not found)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root = _mk_repo(base, "hook")
        _put(root, ".gitignore", "/.githooks/\n/tools/\n/chain/\n*.env\n")
        _paired_readme(root, "# Demo\n\nPlain English text.\n")
        git(root, "add", "--", ".gitignore", "README.md", "README_de.md")
        git(root, "commit", "-q", "-m", "clean")
        clean = git(root, "rev-parse", "HEAD").strip()
        _put(root, "docs/bad.md", "Diese Datei ist nicht leer.\n")
        git(root, "add", "--", "docs/bad.md")
        git(root, "commit", "-q", "-m", "bad")
        bad = git(root, "rev-parse", "HEAD").strip()
        git(root, "reset", "-q", "--hard", clean)
        _put(root, "secret.env", "A=1\n")
        git(root, "add", "-f", "--", "secret.env")
        git(root, "commit", "-q", "-m", "ignored but tracked")
        ign = git(root, "rev-parse", "HEAD").strip()
        git(root, "reset", "-q", "--hard", clean)
        shutil.copytree(hooks, root / ".githooks")
        (root / "tools").mkdir()
        shutil.copy2(script, root / "tools" / "public_check.py")
        (root / "chain").mkdir()
        git(root, "config", "core.hooksPath", str((root / ".githooks").resolve()))
        _put(root, "untracked.md", "Diese Datei ist nicht leer und schmutzig.\n")   # work tree is dirty
        env = dict(os.environ, PYTHON=sys.executable, UJC_CHAINED_HOOKS_PATH=str(root / "chain"))
        zeros = "0" * 40

        def push(stdin_text):
            e = env
            res = subprocess.run([sh, str(root / ".githooks" / "pre-push"), "origin", "https://example.org/r.git"],
                                 input=stdin_text.encode(), cwd=str(root), env=e,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            return res.returncode, res.stderr.decode("utf-8", "replace")

        rc, err = push(f"refs/heads/main {clean} refs/heads/main {zeros}\n")
        expect("hook: pushing a clean commit passes with a dirty work tree", rc == 0)
        rc, err = push(f"refs/heads/main {bad} refs/heads/main {clean}\n")
        expect("hook: pushing a commit with a finding is blocked", rc != 0 and "docs/bad.md" in err)
        rc, err = push(f"refs/heads/main {ign} refs/heads/main {clean}\n")
        expect("hook: pushing a commit with an ignored-but-tracked file is blocked",
               rc != 0 and "secret.env" in err)
        rc, err = push(f"refs/heads/a {clean} refs/heads/a {zeros}\nrefs/heads/b {bad} refs/heads/b {zeros}\n")
        expect("hook: one bad ref of two blocks", rc != 0)
        rc, err = push("")
        expect("hook: empty stdin checks HEAD (clean) instead of nothing", rc == 0 and "--rev HEAD" in err)
        rc, err = push(f"(delete) {zeros} refs/heads/old {clean}\n")
        expect("hook: a deletion alone falls back to HEAD", rc == 0 and "--rev HEAD" in err)
        git(root, "reset", "-q", "--hard", bad)
        rc, err = push("")
        expect("hook: empty stdin with a bad HEAD is blocked", rc != 0)
        git(root, "reset", "-q", "--hard", clean)
        rc, err = push("refs/heads/main 0123456789abcdef0123456789abcdef01234567 refs/heads/main " + zeros + "\n")
        expect("hook: unknown sha fails closed", rc != 0)
        rc, err = push("refs/heads/main not-a-sha refs/heads/main " + zeros + "\n")
        expect("hook: malformed line fails closed", rc != 0)
        rc, err = push(f"refs/heads/main {clean} refs/heads/main {zeros}\n")
        expect("hook: still passes after the failure cases", rc == 0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Public/private gate before commit and push")
    ap.add_argument("--history", action="store_true", help="also check every commit and message")
    ap.add_argument("--staged", action="store_true",
                    help="check the index (what would be committed) instead of the work tree")
    ap.add_argument("--rev", action="append", metavar="COMMIT",
                    help="check the tree of COMMIT, read through git only (repeatable; pre-push)")
    ap.add_argument("--root", help="repository root (default: the repository of this script)")
    ap.add_argument("--stamp", nargs="+", metavar="FILE", help="update source hashes in FILE")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.self_test:
            return self_test()
        root = Path(a.root).resolve() if a.root else Path(__file__).resolve().parent.parent
        root = Path(git(root, "rev-parse", "--show-toplevel").strip())
        if a.stamp:
            return stamp(root, a.stamp)
        if a.rev and a.staged:
            out("ERROR: --rev and --staged cannot be combined")
            return 2
        return run(root, a.history, a.staged, a.rev)
    except GateError as exc:
        out(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
