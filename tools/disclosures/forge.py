#!/usr/bin/env python3
"""Code hosts ("forges") behind one interface: github.com, GitHub Enterprise / own GitHub
servers, Gitea (also Forgejo), GitLab (gitlab.com or self-managed) and plain git
repositories without an API (local path, file://, ssh://, https:// of any git server).

Every tool in tools/disclosures/ speaks the GitHub REST dialect (`repos/<o>/<r>/issues`,
`.../contents/<path>`, ...). This module keeps that: a forge object takes the same GitHub-style
paths, translates them for Gitea and GitLab and returns the answers in GitHub's shape (fields
the tools read: number, title, body, state, html_url, user.login, labels, pull_request, sha,
content, ...). Features a forge does not have (private vulnerability reporting, security
advisories, Dependabot/code-scanning alerts) answer GhNotFound - the same "not available"
the tools already handle for GitHub.

Addressing:

    owner/name                 github.com (unchanged, via the gh CLI)
    <alias>:owner/name         forge <alias> from the .env, e.g. lan:tools/scanner
    <alias>:group/sub/name     GitLab subgroups (more than one slash)

In drafts and register entries the alias is the field "forge" (absent = "github"), the field
"repo" stays owner/name. One block per forge in the .env (see .env.example):

    forge_<alias>_type=github|gitea|gitlab|git
    forge_<alias>_url=https://git.example.org          web base (type git: base path or URL)
    forge_<alias>_api=                                 optional, default per type
    forge_<alias>_token=${vault:ujc-security-checker/forge_<alias>_token}
    forge_<alias>_user=                                user name for git over HTTPS (clone)
    forge_<alias>_ca_bundle=                           PEM file for an own CA
    forge_<alias>_tls_verify=on                        off only for lab hosts (warning)
    forge_<alias>_allow_http=off                       on = plain http allowed (LAN only)
    forge_<alias>_write=off                            on = submit tools may write there
    forge_<alias>_accounts=                            own logins on this host (comma list)
    forge_<alias>_timeout=30

Safety: the token is sent only to the configured API host (no redirect to another host, no
token on a command line, no token over http unless allow_http=on), writes need write=on and
go through the same hash-bound approval as on GitHub. Type git never writes and never runs
code from the repository: reads use a bare cache under .claudex-tmp/forge-cache/ with
protocol.ext disabled and object checks on.

    python tools/disclosures/forge.py list              # configured forges (no secrets)
    python tools/disclosures/forge.py check <alias>     # reachability + login (GET only)
    python tools/disclosures/forge.py --self-test       # no network

Exit 0 ok, 1 check failed, 2 operator error.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common  # noqa: E402
from _common import DisclosureError, GhNotFound, err, out  # noqa: E402

KINDS = ("github", "gitea", "gitlab", "git")
DEFAULT_ALIAS = "github"
ALIAS_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
ON = ("on", "1", "true", "yes")
# GitHub-style path segments that end the repository part of a path (needed for GitLab
# subgroups, where the repository itself may contain more than one slash).
REPO_END = ("issues", "pulls", "commits", "contents", "releases", "private-vulnerability-reporting",
            "security-advisories", "dependabot", "code-scanning", "git")


# --------------------------------------------------------------------------- #
# Addressing
# --------------------------------------------------------------------------- #

def split_target(target: str, forge: str = None):
    """'alias:owner/name' or 'owner/name' (+ optional explicit alias) -> (alias, repo)."""
    target = (target or "").strip()
    alias = forge or DEFAULT_ALIAS
    if ":" in target and not target.startswith(("http://", "https://")):
        a, _, rest = target.partition(":")
        if forge and a != forge:
            raise DisclosureError(f"{target!r} names forge {a!r}, but forge {forge!r} was given")
        alias, target = a, rest
    if not ALIAS_RE.match(alias):
        raise DisclosureError(f"invalid forge alias {alias!r} (a-z, 0-9, _)")
    return alias, target


def qualified(repo: str, forge: str = None) -> str:
    """Key used across tools (watch, register views): owner/name on github, else alias:owner/name."""
    return repo if (forge or DEFAULT_ALIAS) == DEFAULT_ALIAS else f"{forge}:{repo}"


def target_of(meta) -> str:
    """Qualified key of a draft or register entry (fields 'repo' and 'forge')."""
    return qualified(meta.get("repo") or "", meta.get("forge"))


def check_repo_for(kind: str, repo: str) -> str:
    parts = (repo or "").split("/")
    nested = kind in ("gitlab", "git")
    if len(parts) < 2 or (not nested and len(parts) != 2) or len(parts) > 20 \
            or any(p in ("", ".", "..") or not SEGMENT_RE.match(p) for p in parts):
        shape = "group/.../name" if nested else "owner/name"
        raise DisclosureError(f"not a valid {shape} for a {kind} forge: {repo!r}")
    return repo


# --------------------------------------------------------------------------- #
# Configuration from .env / environment
# --------------------------------------------------------------------------- #

FIELDS = ("type", "url", "api", "token", "user", "ca_bundle", "tls_verify", "allow_http", "write",
          "accounts", "timeout")


def _env_values(env_file: Path = None) -> dict:
    """forges= and forge_<alias>_<field> from the .env, environment variables win.
    Values are plain (no vault resolution - only the token may be a vault reference)."""
    values = {}
    path = env_file or _common.ENV_FILE
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k == "forges" or k.startswith("forge_"):
                values[k] = v.split(" #", 1)[0].strip().strip('"').strip("'")
    for k, v in os.environ.items():
        if (k == "forges" or k.startswith("forge_")) and v.strip():
            values[k] = v.strip()
    return values


def configured(env_file: Path = None) -> dict:
    """{alias: {field: value}} of all forges in the .env (github.com is built in)."""
    values = _env_values(env_file)
    aliases = [a.strip() for a in values.get("forges", "").split(",") if a.strip()]
    for k in values:
        m = re.match(r"^forge_([a-z][a-z0-9_]*)_type$", k)
        if m and m.group(1) not in aliases:
            aliases.append(m.group(1))
    res = {}
    for alias in aliases:
        cfg = {}
        for f in FIELDS:
            v = values.get(f"forge_{alias}_{f}")
            if v is not None:
                cfg[f] = v
        res[alias] = cfg
    return res


def _resolve_token(alias: str, raw: str) -> str:
    """Token value; a ${vault:...} reference is resolved via vault_env (UJC_VAULT_ENV)."""
    if not raw or "${vault:" not in raw:
        return raw or ""
    name = f"forge_{alias}_token"
    if "${vault:" not in os.environ.get(name, "${vault:"):
        return os.environ[name]
    vault_env = _common.load_vault_env()
    try:
        vault_env.load_vault_env(str(_common.ENV_FILE), override=False)
    except Exception as exc:  # noqa: BLE001 - the loader raises its own types
        raise DisclosureError(f".env/vault not loadable for {name}: {type(exc).__name__}") from exc
    value = os.environ.get(name, "")
    if not value or "${vault:" in value:
        raise DisclosureError(f"{name} could not be resolved from the vault")
    return value


# --------------------------------------------------------------------------- #
# Forge objects
# --------------------------------------------------------------------------- #

class Forge:
    kind = "?"
    features = frozenset()            # "pvr", "advisory", "confidential_issue", "issues"

    def __init__(self, alias: str, cfg: dict):
        self.alias = alias
        self.cfg = cfg
        self.web = (cfg.get("url") or "").rstrip("/")
        self.write = str(cfg.get("write", "off")).lower() in ON
        self.accounts = [a.strip() for a in str(cfg.get("accounts", "")).split(",") if a.strip()]

    # ----- GitHub-style API (to be implemented) -----
    def get(self, path, forbidden_ok=False):
        raise NotImplementedError

    def get_list(self, path, max_items=1000, forbidden_ok=False):
        raise NotImplementedError

    def post(self, path, payload, method="POST"):
        raise DisclosureError(f"forge {self.alias} ({self.kind}) cannot write")

    def whoami(self) -> str:
        raise NotImplementedError

    def check_repo(self, repo):
        return check_repo_for(self.kind, repo)

    # ----- URLs -----
    def repo_url(self, repo):
        return f"{self.web}/{repo}"

    def blob_url(self, repo, sha, path, lines=None):
        return f"{self.web}/{repo}/blob/{sha}/{path}" + (f"#L{lines.replace('-', '-L')}" if lines else "")

    def commit_url(self, repo, sha):
        return f"{self.web}/{repo}/commit/{sha}"

    def policy_page(self, repo):
        return None

    def clone_url(self, repo):
        return f"{self.web}/{repo}.git"

    def permalink_hint(self, repo):
        """One sentence for the Codex prompt: how permalinks of this forge look."""
        return f"{self.web}/{repo}/blob/<sha>/<path>#L<a>-L<b>"

    def describe(self) -> dict:
        return {"alias": self.alias, "type": self.kind, "url": self.web,
                "api": getattr(self, "api", "") or "-", "write": "on" if self.write else "off",
                "token": "set" if self.cfg.get("token") else "-",
                "features": ",".join(sorted(self.features)) or "-"}


class GitHubForge(Forge):
    """github.com (alias 'github') or a GitHub Enterprise Server via gh --hostname."""
    kind = "github"
    features = frozenset({"pvr", "advisory", "issues"})

    def __init__(self, alias, cfg):
        super().__init__(alias, cfg)
        if alias == DEFAULT_ALIAS and not self.web:
            self.web = "https://github.com"
            self.write = True            # unchanged behaviour: the approval gates writes
        self.host = urlsplit(self.web).hostname or "github.com"
        self.api = cfg.get("api") or ("https://api.github.com" if self.host == "github.com"
                                      else f"{self.web}/api/v3")

    def _gh(self, argv, stdin=None):
        if self.host == "github.com":
            return _common._gh(argv, stdin)
        env = dict(os.environ)
        token = _resolve_token(self.alias, self.cfg.get("token", ""))
        if token:
            env["GH_ENTERPRISE_TOKEN"] = token
        env["GH_HOST"] = self.host
        try:
            return subprocess.run(["gh", argv[0], "--hostname", self.host, *argv[1:]],
                                  capture_output=True, text=True, encoding="utf-8",
                                  input=stdin, env=env)
        except FileNotFoundError as exc:
            raise DisclosureError("gh CLI not found") from exc

    def get(self, path, forbidden_ok=False):
        if self.host == "github.com":
            return _common.gh_get(path, forbidden_ok)
        proc = self._gh(["api", "-X", "GET", "-H", "Accept: application/vnd.github+json", path])
        if proc.returncode != 0:
            _common._gh_failed(path, (proc.stderr or proc.stdout or "").strip(), forbidden_ok)
        text = proc.stdout.strip()
        return json.loads(text) if text else None

    def get_list(self, path, max_items=1000, forbidden_ok=False):
        if self.host == "github.com":
            return _common.gh_get_list(path, max_items, forbidden_ok)
        proc = self._gh(["api", "-X", "GET", "--paginate", "-H", "Accept: application/vnd.github+json",
                         path, "--jq", ".[]"])
        if proc.returncode != 0:
            _common._gh_failed(path, (proc.stderr or proc.stdout or "").strip(), forbidden_ok)
        items = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
        return items[:max_items]

    def post(self, path, payload, method="POST"):
        if not self.write:
            raise DisclosureError(f"forge {self.alias}: writing is off (forge_{self.alias}_write=on in .env)")
        if self.host == "github.com":
            return _common.gh_post(path, payload, method)
        if method not in ("POST", "PATCH"):
            raise DisclosureError(f"method {method} not allowed")
        proc = self._gh(["api", "-X", method, "-H", "Accept: application/vnd.github+json",
                         path, "--input", "-"], stdin=json.dumps(payload))
        if proc.returncode != 0:
            raise DisclosureError(f"gh api {method} {path} ({self.host}) failed: "
                                  + (proc.stderr or proc.stdout or "").strip()[:500])
        return json.loads(proc.stdout) if proc.stdout.strip() else {}

    def whoami(self):
        if self.host == "github.com":
            return _common.gh_logged_in()
        proc = self._gh(["api", "-X", "GET", "user", "--jq", ".login"])
        if proc.returncode != 0 or not proc.stdout.strip():
            raise DisclosureError(f"gh is not logged in at {self.host}: " + (proc.stderr or "").strip()[:200])
        return proc.stdout.strip()

    def policy_page(self, repo):
        return f"{self.web}/{repo}/security/policy"


# ----- HTTP transport for Gitea and GitLab --------------------------------- #

class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Follows redirects only to the same scheme+host+port - the token never leaves the host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        a, b = urlsplit(req.full_url), urlsplit(newurl)
        if (a.scheme, a.netloc) != (b.scheme, b.netloc):
            raise DisclosureError(f"redirect to another host refused: {a.netloc} -> {b.netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpResponse:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body.decode("utf-8")) if self.body.strip() else None


class HttpForge(Forge):
    default_api = ""

    def __init__(self, alias, cfg, transport=None):
        super().__init__(alias, cfg)
        if not self.web:
            raise DisclosureError(f"forge_{alias}_url missing")
        self.api = (cfg.get("api") or f"{self.web}{self.default_api}").rstrip("/")
        scheme = urlsplit(self.api).scheme
        if scheme not in ("https", "http"):
            raise DisclosureError(f"forge {alias}: API URL must be http(s): {self.api}")
        if scheme == "http" and str(cfg.get("allow_http", "off")).lower() not in ON:
            raise DisclosureError(f"forge {alias}: plain http refused (token in clear text) - "
                                  f"use https or set forge_{alias}_allow_http=on for a LAN host")
        self.timeout = int(cfg.get("timeout") or 30)
        self.transport = transport or self._urllib
        self._token = None

    # -- transport --
    def token(self):
        if self._token is None:
            self._token = _resolve_token(self.alias, self.cfg.get("token", ""))
        return self._token

    def _ssl(self):
        ctx = ssl.create_default_context(cafile=self.cfg.get("ca_bundle") or None)
        if str(self.cfg.get("tls_verify", "on")).lower() not in ON:
            err(f"WARNING: forge {self.alias}: TLS verification is OFF")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def auth_headers(self):
        raise NotImplementedError

    def _urllib(self, method, url, headers, body):
        opener = urllib.request.build_opener(_SameHostRedirect(),
                                             urllib.request.HTTPSHandler(context=self._ssl()))
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with opener.open(req, timeout=self.timeout) as r:
                return HttpResponse(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as exc:
            return HttpResponse(exc.code, dict(exc.headers or {}), exc.read() or b"")
        except (urllib.error.URLError, OSError) as exc:
            raise DisclosureError(f"forge {self.alias}: {method} {urlsplit(url).path} failed: "
                                  f"{getattr(exc, 'reason', exc)}") from exc

    def request(self, method, apipath, params=None, payload=None, forbidden_ok=False):
        url = f"{self.api}/{apipath.lstrip('/')}"
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        headers = {"Accept": "application/json", "User-Agent": "ujc-security-checker", **self.auth_headers()}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        r = self.transport(method, url, headers, body)
        if r.status == 404 or (forbidden_ok and r.status in (401, 403)):
            raise GhNotFound(f"HTTP {r.status} {apipath}")
        if r.status in (401, 403):
            raise DisclosureError(f"forge {self.alias}: {method} {apipath} forbidden (HTTP {r.status}: "
                                  "token, permission or rate limit - not 'not found')")
        if r.status >= 400:
            raise DisclosureError(f"forge {self.alias}: {method} {apipath} failed: HTTP {r.status} "
                                  + r.body.decode("utf-8", "replace")[:300])
        return r

    def _write_guard(self):
        if not self.write:
            raise DisclosureError(f"forge {self.alias}: writing is off (forge_{self.alias}_write=on in .env)")

    @staticmethod
    def split_path(path):
        """'repos/<repo>/<rest>?q' -> (repo, rest, query dict); other paths -> (None, path, query)."""
        p, _, q = path.partition("?")
        query = dict(parse_qsl(q))
        if not p.startswith("repos/"):
            return None, p, query
        parts = p[len("repos/"):].split("/")
        cut = next((i for i in range(2, len(parts)) if parts[i] in REPO_END), len(parts))
        return "/".join(parts[:cut]), "/".join(parts[cut:]), query


def _clean_pr_field(item):
    """GitHub semantics: the key 'pull_request' exists only for PRs."""
    if isinstance(item, dict) and item.get("pull_request") is None:
        item.pop("pull_request", None)
    return item


class GiteaForge(HttpForge):
    """Gitea / Forgejo: /api/v1 mirrors most GitHub paths."""
    kind = "gitea"
    features = frozenset({"issues"})
    default_api = "/api/v1"
    page_size = 50

    def auth_headers(self):
        t = self.token()
        return {"Authorization": f"token {t}"} if t else {}

    def blob_url(self, repo, sha, path, lines=None):
        return f"{self.web}/{repo}/src/commit/{sha}/{path}" + (f"#L{lines.replace('-', '-L')}" if lines else "")

    def permalink_hint(self, repo):
        return f"{self.web}/{repo}/src/commit/<sha>/<path>#L<a>-L<b>"

    def _pages(self, apipath, params, max_items, forbidden_ok=False):
        items, page = [], 1
        params = {k: v for k, v in params.items() if k not in ("per_page", "page", "sort", "direction")}
        while len(items) < max_items:
            r = self.request("GET", apipath, {**params, "page": page, "limit": self.page_size}, None, forbidden_ok)
            batch = r.json() or []
            if not isinstance(batch, list):
                raise DisclosureError(f"forge {self.alias}: {apipath} did not return a list")
            items += batch
            if len(batch) < self.page_size:
                break
            page += 1
        return items[:max_items]

    def get(self, path, forbidden_ok=False):
        repo, rest, q = self.split_path(path)
        if repo is None:
            if rest == "user":
                return self.request("GET", "user").json()
            if rest.startswith("search/issues"):
                return self._search(q)
            return self.request("GET", path, None, None, forbidden_ok).json()
        if rest.split("/")[0] in ("private-vulnerability-reporting", "security-advisories",
                                  "dependabot", "code-scanning"):
            raise GhNotFound(f"{rest.split('/')[0]} is not available on Gitea")
        m = re.fullmatch(r"commits/(.+)", rest)
        if m:
            return self._commit(repo, m.group(1))
        data = self.request("GET", f"repos/{repo}" + (f"/{rest}" if rest else ""),
                            q or None, None, forbidden_ok).json()
        return _clean_pr_field(data)

    def _commit(self, repo, ref):
        ref = urllib.request.unquote(ref)
        for kind, getter in (("branches", lambda d: ((d.get("commit") or {}).get("id"),
                                                      (d.get("commit") or {}).get("timestamp"))),
                             ("tags", lambda d: ((d.get("commit") or {}).get("sha"),
                                                 (d.get("commit") or {}).get("created")))):
            if SHA40.match(ref):
                break
            try:
                d = self.request("GET", f"repos/{repo}/{kind}/{quote(ref, safe='')}").json() or {}
                sha, date = getter(d)
                if sha:
                    return {"sha": sha, "commit": {"committer": {"date": date}}}
            except GhNotFound:
                continue
        d = self.request("GET", f"repos/{repo}/git/commits/{quote(ref, safe='')}").json() or {}
        return {"sha": d.get("sha"), "commit": d.get("commit") or {}}

    def _search(self, q):
        query = q.get("q", "")
        m = re.match(r"repo:(\S+)\s*(.*)", query)
        if not m:
            raise DisclosureError("search on Gitea needs 'repo:<owner/name> words'")
        repo = m.group(1).split(":", 1)[-1]
        hits = self._pages(f"repos/{repo}/issues", {"state": "all", "q": m.group(2)},
                           int(q.get("per_page", 20)))
        return {"items": [_clean_pr_field(h) for h in hits]}

    def get_list(self, path, max_items=1000, forbidden_ok=False):
        repo, rest, q = self.split_path(path)
        if repo is not None and rest.split("/")[0] in ("security-advisories", "dependabot", "code-scanning"):
            raise GhNotFound(f"{rest.split('/')[0]} is not available on Gitea")
        if repo is not None and re.fullmatch(r"issues/\d+/timeline", rest):
            return self._timeline(repo, rest, max_items)
        apipath = f"repos/{repo}/{rest}" if repo is not None else path.partition("?")[0]
        if repo is None and rest.startswith("users/") and rest.endswith("/repos"):
            apipath = rest
        items = self._pages(apipath, q, max_items, forbidden_ok)
        if rest == "issues":
            sort = "created_at" if q.get("sort") == "created" else "updated_at"
            items.sort(key=lambda x: x.get(sort) or "", reverse=q.get("direction") == "desc")
        return [_clean_pr_field(x) for x in items]

    def _timeline(self, repo, rest, max_items):
        try:
            raw = self._pages(f"repos/{repo}/{rest}", {}, max_items)
        except GhNotFound:
            return []                          # older Gitea without a timeline API
        events = []
        for ev in raw:
            t = ev.get("type")
            ref = ev.get("ref_issue") or {}
            if t == "pull_ref" and ref:
                events.append({"event": "cross-referenced", "source": {"issue": {
                    "number": ref.get("number"), "pull_request": {},
                    "repository": {"full_name": (ref.get("repository") or {}).get("full_name") or repo}}}})
            elif t in ("commit_ref", "close") and ev.get("ref_commit_sha"):
                events.append({"event": "referenced" if t == "commit_ref" else "closed",
                               "commit_id": ev["ref_commit_sha"]})
        return events

    def post(self, path, payload, method="POST"):
        self._write_guard()
        repo, rest, _ = self.split_path(path)
        if repo is None:
            raise DisclosureError(f"forge {self.alias}: write path not supported: {path}")
        if re.fullmatch(r"issues/\d+", rest) and method == "PATCH":
            payload = {k: v for k, v in payload.items() if k != "state_reason"}
        elif method != "POST" or not re.fullmatch(r"issues|issues/\d+/comments|issues/\d+/labels", rest):
            raise DisclosureError(f"forge {self.alias}: write path not supported: {method} {rest}")
        if payload.get("confidential"):
            raise DisclosureError("Gitea has no confidential issues - use mail or another channel")
        return self.request(method, f"repos/{repo}/{rest}", None, payload).json() or {}

    def whoami(self):
        return (self.request("GET", "user").json() or {}).get("login") or ""


class GitLabForge(HttpForge):
    """GitLab: /api/v4 with project IDs; answers mapped to GitHub's shape.
    Merge requests are reached via issue links and pulls/<n>; the repository-wide issue list
    contains issues only (MR numbers would collide with issue numbers)."""
    kind = "gitlab"
    features = frozenset({"confidential_issue", "issues"})
    default_api = "/api/v4"
    page_size = 100

    def auth_headers(self):
        t = self.token()
        return {"PRIVATE-TOKEN": t} if t else {}

    def blob_url(self, repo, sha, path, lines=None):
        return f"{self.web}/{repo}/-/blob/{sha}/{path}" + (f"#L{lines}" if lines else "")

    def commit_url(self, repo, sha):
        return f"{self.web}/{repo}/-/commit/{sha}"

    def permalink_hint(self, repo):
        return f"{self.web}/{repo}/-/blob/<sha>/<path>#L<a>-<b>"

    @staticmethod
    def pid(repo):
        return quote(repo, safe="")

    def _pages(self, apipath, params, max_items, forbidden_ok=False):
        items, page = [], 1
        while len(items) < max_items:
            r = self.request("GET", apipath, {**params, "page": page, "per_page": self.page_size},
                             None, forbidden_ok)
            batch = r.json() or []
            if not isinstance(batch, list):
                raise DisclosureError(f"forge {self.alias}: {apipath} did not return a list")
            items += batch
            nxt = {k.lower(): v for k, v in r.headers.items()}.get("x-next-page", "")
            if not str(nxt).strip() or len(batch) < self.page_size:
                break
            page = int(nxt)
        return items[:max_items]

    # -- mapping to GitHub's shape --
    @staticmethod
    def _user(u):
        u = u or {}
        return {"login": u.get("username") or "", "type": "Bot" if u.get("bot") else "User"}

    def _issue(self, x):
        return {"number": x.get("iid"), "title": x.get("title"), "body": x.get("description") or "",
                "state": "open" if x.get("state") == "opened" else "closed", "state_reason": None,
                "html_url": x.get("web_url"), "user": self._user(x.get("author")),
                "labels": [{"name": n} for n in x.get("labels") or []],
                "created_at": x.get("created_at"), "updated_at": x.get("updated_at"),
                "comments": x.get("user_notes_count"), "confidential": bool(x.get("confidential"))}

    def _mr(self, x):
        merged = x.get("state") == "merged"
        return {"number": x.get("iid"), "title": x.get("title"), "body": x.get("description") or "",
                "html_url": x.get("web_url"), "user": self._user(x.get("author")),
                "merged": merged, "merged_at": x.get("merged_at"),
                "merge_commit_sha": x.get("merge_commit_sha") or x.get("squash_commit_sha"),
                "state": "open" if x.get("state") == "opened" else "closed",
                "base": {"ref": x.get("target_branch")}, "head": {"sha": x.get("sha")},
                "pull_request": {}, "created_at": x.get("created_at"), "updated_at": x.get("updated_at")}

    def _project(self, repo):
        x = self.request("GET", f"projects/{self.pid(repo)}").json() or {}
        return {"full_name": x.get("path_with_namespace") or repo, "default_branch": x.get("default_branch"),
                "archived": x.get("archived"), "fork": bool(x.get("forked_from_project")),
                "private": x.get("visibility") != "public", "visibility": x.get("visibility"),
                "html_url": x.get("web_url")}

    def get(self, path, forbidden_ok=False):
        repo, rest, q = self.split_path(path)
        if repo is None:
            if rest == "user":
                return {"login": (self.request("GET", "user").json() or {}).get("username")}
            if rest.startswith("search/issues"):
                return self._search(q)
            raise DisclosureError(f"forge {self.alias}: path not supported on GitLab: {path}")
        p = f"projects/{self.pid(repo)}"
        head = rest.split("/")[0]
        if head in ("private-vulnerability-reporting", "security-advisories", "dependabot", "code-scanning"):
            raise GhNotFound(f"{head} is not available on GitLab")
        if rest == "":
            return self._project(repo)
        m = re.fullmatch(r"commits/(.+)", rest)
        if m:
            c = self.request("GET", f"{p}/repository/commits/{quote(urllib.request.unquote(m.group(1)), safe='')}").json() or {}
            return {"sha": c.get("id"), "commit": {"committer": {"date": c.get("committed_date")}}}
        if rest == "releases/latest":
            r = self.request("GET", f"{p}/releases/permalink/latest").json() or {}
            return {"tag_name": r.get("tag_name"), "published_at": r.get("released_at")}
        m = re.fullmatch(r"contents/(.+)", rest)
        if m:
            ref = q.get("ref") or self._project(repo)["default_branch"]
            f = self.request("GET", f"{p}/repository/files/{quote(urllib.request.unquote(m.group(1)), safe='')}",
                             {"ref": ref}).json() or {}
            return {"type": "file", "sha": f.get("blob_id"), "content": f.get("content", ""),
                    "encoding": f.get("encoding"), "path": f.get("file_path")}
        m = re.fullmatch(r"issues/(\d+)", rest)
        if m:
            return self._issue(self.request("GET", f"{p}/issues/{m.group(1)}").json() or {})
        m = re.fullmatch(r"pulls/(\d+)", rest)
        if m:
            return self._mr(self.request("GET", f"{p}/merge_requests/{m.group(1)}").json() or {})
        raise DisclosureError(f"forge {self.alias}: path not supported on GitLab: {rest}")

    def _search(self, q):
        m = re.match(r"repo:(\S+)\s*(.*)", q.get("q", ""))
        if not m:
            raise DisclosureError("search on GitLab needs 'repo:<group/name> words'")
        repo = m.group(1).split(":", 1)[-1]
        p = f"projects/{self.pid(repo)}"
        n = int(q.get("per_page", 20))
        items = [self._issue(x) for x in self._pages(f"{p}/issues", {"search": m.group(2)}, n)]
        items += [self._mr(x) for x in self._pages(f"{p}/merge_requests", {"search": m.group(2)}, n)]
        return {"items": items}

    def get_list(self, path, max_items=1000, forbidden_ok=False):
        repo, rest, q = self.split_path(path)
        if repo is None:
            m = re.fullmatch(r"users/([^/]+)/repos", rest)
            if m:
                return [{"full_name": x.get("path_with_namespace"), "default_branch": x.get("default_branch"),
                         "archived": x.get("archived"), "fork": bool(x.get("forked_from_project")),
                         "private": x.get("visibility") != "public", "visibility": x.get("visibility"),
                         "html_url": x.get("web_url")}
                        for x in self._pages(f"users/{m.group(1)}/projects", {}, max_items, forbidden_ok)]
            raise DisclosureError(f"forge {self.alias}: path not supported on GitLab: {path}")
        p = f"projects/{self.pid(repo)}"
        head = rest.split("/")[0]
        if head in ("security-advisories", "dependabot", "code-scanning"):
            raise GhNotFound(f"{head} is not available on GitLab")
        if rest == "issues":
            params = {"scope": "all", "order_by": "created_at" if q.get("sort") == "created" else "updated_at",
                      "sort": "desc" if q.get("direction") == "desc" else "asc"}
            if q.get("state") in ("open", "closed"):
                params["state"] = "opened" if q["state"] == "open" else "closed"
            if q.get("since"):
                params["updated_after"] = q["since"]
            return [self._issue(x) for x in self._pages(f"{p}/issues", params, max_items, forbidden_ok)]
        m = re.fullmatch(r"issues/(\d+)/comments", rest)
        if m:
            web = (self.request("GET", f"{p}/issues/{m.group(1)}").json() or {}).get("web_url") or ""
            notes = self._pages(f"{p}/issues/{m.group(1)}/notes", {"sort": "asc", "order_by": "created_at"}, max_items)
            return [{"id": n.get("id"), "body": n.get("body") or "", "user": self._user(n.get("author")),
                     "created_at": n.get("created_at"), "updated_at": n.get("updated_at"),
                     "html_url": f"{web}#note_{n.get('id')}", "author_association": None}
                    for n in notes if not n.get("system")]
        m = re.fullmatch(r"issues/(\d+)/timeline", rest)
        if m:
            return self._timeline(repo, p, m.group(1), max_items)
        m = re.fullmatch(r"pulls/(\d+)/files", rest)
        if m:
            return [{"filename": d.get("new_path")}
                    for d in self._pages(f"{p}/merge_requests/{m.group(1)}/diffs", {}, max_items)]
        if re.fullmatch(r"pulls/\d+/reviews", rest):
            return []                          # GitLab approvals are not mapped
        raise DisclosureError(f"forge {self.alias}: path not supported on GitLab: {rest}")

    def _timeline(self, repo, p, nr, max_items):
        events = []
        for mr in self._pages(f"{p}/issues/{nr}/related_merge_requests", {}, max_items):
            full = str((mr.get("references") or {}).get("full") or "").split("!", 1)[0] or repo
            events.append({"event": "cross-referenced", "source": {"issue": {
                "number": mr.get("iid"), "pull_request": {}, "repository": {"full_name": full}}}})
        for n in self._pages(f"{p}/issues/{nr}/notes", {"sort": "asc"}, max_items):
            if n.get("system"):
                m = re.search(r"\b(?:mentioned in|closed via) commit (?:[\w./-]+@)?([0-9a-f]{7,40})\b",
                              n.get("body") or "")
                if m:
                    events.append({"event": "closed" if "closed via" in n["body"] else "referenced",
                                   "commit_id": m.group(1)})
        return events

    def post(self, path, payload, method="POST"):
        self._write_guard()
        repo, rest, _ = self.split_path(path)
        if repo is None:
            raise DisclosureError(f"forge {self.alias}: write path not supported: {path}")
        p = f"projects/{self.pid(repo)}"
        if method == "POST" and rest == "issues":
            body = {"title": payload.get("title"), "description": payload.get("body", "")}
            if payload.get("confidential"):
                body["confidential"] = True
            x = self.request("POST", f"{p}/issues", None, body).json() or {}
            res = self._issue(x)
            if payload.get("confidential") and not res["confidential"]:
                raise DisclosureError(f"GitLab created issue {res['number']} WITHOUT confidential - "
                                      f"make it confidential by hand now: {res['html_url']}")
            return res
        m = re.fullmatch(r"issues/(\d+)/comments", rest)
        if method == "POST" and m:
            n = self.request("POST", f"{p}/issues/{m.group(1)}/notes", None, {"body": payload.get("body", "")}).json() or {}
            web = (self.request("GET", f"{p}/issues/{m.group(1)}").json() or {}).get("web_url") or ""
            return {"id": n.get("id"), "html_url": f"{web}#note_{n.get('id')}", "created_at": n.get("created_at")}
        m = re.fullmatch(r"issues/(\d+)/labels", rest)
        if method == "POST" and m:
            return self.request("PUT", f"{p}/issues/{m.group(1)}", None,
                                {"add_labels": ",".join(payload.get("labels") or [])}).json() or {}
        m = re.fullmatch(r"issues/(\d+)", rest)
        if method == "PATCH" and m and payload.get("state") == "closed":
            return self.request("PUT", f"{p}/issues/{m.group(1)}", None, {"state_event": "close"}).json() or {}
        raise DisclosureError(f"forge {self.alias}: write path not supported on GitLab: {method} {rest}")

    def whoami(self):
        return (self.request("GET", "user").json() or {}).get("username") or ""


# ----- plain git repositories (no API) -------------------------------------- #

# A ref never starts with '-' (it would be read as a git option); no '..'
GIT_REF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,199}$")
GIT_SAFE = ["-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=always",
            "-c", "transfer.fsckObjects=true", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]


def git_env(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                "GCM_INTERACTIVE": "never"})
    env.update(extra or {})
    return env


class GitForge(Forge):
    """No API: local path, file://, ssh:// or https:// git URLs. Read-only; files are read from
    a bare cache, no issue tracker, no writing - disclosures go by mail."""
    kind = "git"
    features = frozenset()

    def __init__(self, alias, cfg, runner=None):
        super().__init__(alias, cfg)
        if not self.web:
            raise DisclosureError(f"forge_{alias}_url missing (base path or URL of the git server)")
        self.write = False
        self.runner = runner or self._run

    def clone_url(self, repo):
        base = self.web
        if re.match(r"^[A-Za-z]:[\\/]|^/|^\\\\", base) and not base.startswith("file:"):
            return str(Path(base) / Path(*repo.split("/")))
        return f"{base}/{repo}"

    def repo_url(self, repo):
        return self.clone_url(repo)

    def blob_url(self, repo, sha, path, lines=None):
        return f"{self.clone_url(repo)}@{sha}:{path}" + (f"#L{lines}" if lines else "")

    def commit_url(self, repo, sha):
        return f"{self.clone_url(repo)}@{sha}"

    def permalink_hint(self, repo):
        return f"{self.clone_url(repo)}@<sha>:<path>#L<a>-<b> (no web UI)"

    def _run(self, args, cwd=None):
        r = subprocess.run(["git", *GIT_SAFE, *args], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=cwd, env=git_env(), timeout=600)
        return r.returncode, r.stdout, r.stderr

    @staticmethod
    def read_blob(cache, blob) -> bytes:
        """Bytes of a blob from the bare cache (binary-safe, no text decoding)."""
        r = subprocess.run(["git", *GIT_SAFE, "-C", str(cache), "cat-file", "blob", blob],
                           capture_output=True, env=git_env(), timeout=120)
        if r.returncode != 0:
            raise DisclosureError(f"git cat-file {blob[:12]} failed")
        return r.stdout

    def _cache(self, repo):
        d = _common.ROOT / ".claudex-tmp" / "forge-cache" / self.alias / (repo.replace("/", "__") + ".git")
        if not d.exists():
            d.parent.mkdir(parents=True, exist_ok=True)
            rc, _o, e = self.runner(["init", "--bare", "-q", str(d)])
            if rc != 0:
                raise DisclosureError(f"git init of the cache failed: {e.strip()[:200]}")
        return d

    def _ls_remote(self, repo, *refs):
        rc, o, e = self.runner(["ls-remote", "--symref", self.clone_url(repo), *refs])
        if rc != 0:
            raise GhNotFound(f"git ls-remote {repo}: {e.strip()[:200]}")
        return o

    def _resolve(self, repo, ref):
        if SHA40.match(ref):
            return ref
        if not GIT_REF_RE.match(ref or "") or ".." in ref:
            raise DisclosureError(f"not a plain branch or tag name: {ref!r}")
        o = self._ls_remote(repo, ref, f"refs/heads/{ref}", f"refs/tags/{ref}")
        for line in o.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and SHA40.match(parts[0]) and not parts[1].endswith("^{}"):
                return parts[0]
        raise GhNotFound(f"ref {ref} not found in {repo}")

    def get(self, path, forbidden_ok=False):
        repo, rest, q = HttpForge.split_path(path)
        if repo is None:
            if rest == "user":
                return {"login": ""}
            raise DisclosureError(f"forge {self.alias} (git) has no API for {path}")
        if rest == "":
            o = self._ls_remote(repo, "HEAD")
            m = re.search(r"^ref: refs/heads/(\S+)\tHEAD", o, re.M)
            return {"full_name": repo, "default_branch": m.group(1) if m else "main",
                    "archived": None, "fork": None, "private": None, "html_url": self.repo_url(repo)}
        m = re.fullmatch(r"commits/(.+)", rest)
        if m:
            return {"sha": self._resolve(repo, urllib.request.unquote(m.group(1))), "commit": {}}
        m = re.fullmatch(r"contents/(.+)", rest)
        if m:
            ref = q.get("ref") or self.get(f"repos/{repo}")["default_branch"]
            sha = self._resolve(repo, ref)
            cache = self._cache(repo)
            rc, _o, e = self.runner(["-C", str(cache), "fetch", "-q", "--depth", "1", "--no-tags",
                                     self.clone_url(repo), sha])
            if rc != 0:
                raise DisclosureError(f"git fetch {repo}@{sha[:12]} failed: {e.strip()[:200]}")
            fpath = urllib.request.unquote(m.group(1))
            rc, blob, _e = self.runner(["-C", str(cache), "rev-parse", f"{sha}:{fpath}"])
            if rc != 0:
                raise GhNotFound(f"{fpath} not in {repo}@{sha[:12]}")
            blob = blob.strip()
            raw = self.read_blob(cache, blob)
            return {"type": "file", "sha": blob, "content": base64.b64encode(raw).decode("ascii"),
                    "encoding": "base64", "path": fpath}
        raise GhNotFound(f"{rest.split('/')[0]} is not available for plain git repositories")

    def get_list(self, path, max_items=1000, forbidden_ok=False):
        raise GhNotFound("plain git repositories have no issue tracker or lists")

    def whoami(self):
        return ""


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_CACHE = {}


def get_forge(alias: str = None, env_file: Path = None) -> Forge:
    alias = alias or DEFAULT_ALIAS
    key = (alias, str(env_file or _common.ENV_FILE))
    if key in _CACHE:
        return _CACHE[key]
    cfgs = configured(env_file)
    if alias == DEFAULT_ALIAS:
        cfg = cfgs.get(alias, {})
        if cfg.get("type", "github") != "github" or cfg.get("url"):
            raise DisclosureError("alias 'github' is reserved for github.com - give the server another alias")
        f = GitHubForge(alias, {k: v for k, v in cfg.items() if k == "accounts"})
    else:
        if alias not in cfgs:
            raise DisclosureError(f"forge {alias!r} is not configured (forge_{alias}_type/_url in .env)")
        cfg = cfgs[alias]
        kind = cfg.get("type", "")
        if kind not in KINDS:
            raise DisclosureError(f"forge_{alias}_type={kind!r} - allowed {KINDS}")
        if kind == "github" and not cfg.get("url"):
            raise DisclosureError(f"forge_{alias}_url missing (GitHub Enterprise / own server)")
        f = {"github": GitHubForge, "gitea": GiteaForge, "gitlab": GitLabForge, "git": GitForge}[kind](alias, cfg)
    _CACHE[key] = f
    return f


def forge_of(meta) -> Forge:
    """Forge of a draft or register entry (field 'forge', absent = github)."""
    return get_forge(meta.get("forge") or DEFAULT_ALIAS)


def resolve(target: str, forge: str = None):
    """'alias:owner/name' -> (Forge, repo), with the repository checked for that forge."""
    alias, repo = split_target(target, forge)
    f = get_forge(alias)
    return f, f.check_repo(repo)


class Router:
    """GitHub-style source for disclosure_watch: routes 'repos/<alias>:<repo>/...' to the forge."""

    def __init__(self, forges=None):
        self.forges = forges or {}

    def _split(self, path):
        if path.startswith("repos/"):
            rest = path[len("repos/"):]
            m = re.match(r"^([a-z][a-z0-9_]*):(.*)$", rest)
            if m:
                f = self.forges.get(m.group(1)) or get_forge(m.group(1))
                return f, "repos/" + m.group(2)
        return self.forges.get(DEFAULT_ALIAS) or get_forge(DEFAULT_ALIAS), path

    def get(self, path, forbidden_ok=False):
        f, p = self._split(path)
        return f.get(p, forbidden_ok=forbidden_ok)

    def list(self, path, max_items=1000, forbidden_ok=False):
        f, p = self._split(path)
        return f.get_list(p, max_items, forbidden_ok=forbidden_ok)


# --------------------------------------------------------------------------- #
# CLI and self-test
# --------------------------------------------------------------------------- #

def cmd_list() -> int:
    rows = [get_forge(DEFAULT_ALIAS).describe()]
    for alias in configured():
        if alias == DEFAULT_ALIAS:
            continue
        try:
            rows.append(get_forge(alias).describe())
        except DisclosureError as exc:
            rows.append({"alias": alias, "type": "ERROR", "url": str(exc)[:80], "api": "-", "write": "-",
                         "token": "-", "features": "-"})
    for r in rows:
        out(f"{r['alias']:<14} {r['type']:<7} write={r['write']:<3} token={r['token']:<3} "
            f"features={r['features']:<34} {r['url']}")
    return 0


def cmd_check(alias: str, repo: str = None) -> int:
    f = get_forge(alias)
    who = f.whoami()
    out(f"{alias}: reachable ({f.kind}), login: {who or '- (anonymous or no API)'}")
    if repo:
        info = f.get(f"repos/{f.check_repo(repo)}")
        out(f"{repo}: default branch {info.get('default_branch')}, private={info.get('private')}")
    return 0


class FakeTransport:
    """Answers (method, path-without-api, sorted query) -> (status, body, headers)."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, headers, body):
        u = urlsplit(url)
        path = u.path.split("/api/v", 1)[-1].split("/", 1)[-1]
        q = dict(parse_qsl(u.query))
        self.calls.append((method, path, q, headers, json.loads(body) if body else None))
        for (m, p), answer in self.routes.items():
            if m == method and (p == path or (p.endswith("*") and path.startswith(p[:-1]))):
                a = answer(q) if callable(answer) else answer
                status, data, hdr = a if isinstance(a, tuple) else (200, a, {})
                return HttpResponse(status, hdr, json.dumps(data).encode())
        return HttpResponse(404, {}, b'{"message":"not found"}')


def self_test() -> int:
    import tempfile

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    def raises(fn, exc=DisclosureError):
        try:
            fn()
        except exc:
            return True
        except Exception:  # noqa: BLE001
            return False
        return False

    saved_env = {k: os.environ.pop(k) for k in list(os.environ) if k == "forges" or k.startswith("forge_")}
    saved_file = _common.ENV_FILE
    try:
        with tempfile.TemporaryDirectory() as td:
            _common.ENV_FILE = Path(td) / ".env"
            _common.ENV_FILE.write_text(
                "forges=lan,corp\n"
                "forge_lan_type=gitea\nforge_lan_url=http://git.example.net:3000\nforge_lan_allow_http=on\n"
                "forge_lan_token=t-lan   # comment\nforge_lan_write=on\n"
                "forge_corp_type=gitlab\nforge_corp_url=https://gitlab.example.org\nforge_corp_token=t-gl\n"
                "forge_ghe_type=github\nforge_ghe_url=https://ghe.example.org\n"
                "forge_raw_type=git\nforge_raw_url=/srv/git\n"
                "forge_bad_type=gitea\nforge_bad_url=http://x\n", encoding="utf-8")
            _CACHE.clear()
            # Addressing
            check("split plain", split_target("o/n") == ("github", "o/n"))
            check("split alias", split_target("lan:o/n") == ("lan", "o/n"))
            check("split conflicting alias", raises(lambda: split_target("lan:o/n", "corp")))
            check("qualified", qualified("o/n") == "o/n" and qualified("o/n", "lan") == "lan:o/n")
            check("gitlab subgroup ok", check_repo_for("gitlab", "g/s/n") == "g/s/n")
            check("gitea subgroup refused", raises(lambda: check_repo_for("gitea", "g/s/n")))
            check("dotdot refused", raises(lambda: check_repo_for("gitlab", "g/../n")))
            # Configuration
            cfg = configured()
            check("forges discovered", set(cfg) == {"lan", "corp", "ghe", "raw", "bad"})
            check("inline comment cut", cfg["lan"]["token"] == "t-lan")
            check("http refused without allow_http", raises(lambda: get_forge("bad")))
            check("unknown alias", raises(lambda: get_forge("nope")))
            ghe = get_forge("ghe")
            check("GHES host and API", (ghe.host, ghe.api) == ("ghe.example.org", "https://ghe.example.org/api/v3"))
            check("GHES write off by default", raises(lambda: ghe.post("repos/o/n/issues", {})))
            check("github.com write on", get_forge("github").write is True)
            check("git forge never writes", get_forge("raw").write is False
                  and raises(lambda: get_forge("raw").post("repos/o/n/issues", {})))
            check("git forge: option-like ref refused",
                  raises(lambda: get_forge("raw")._resolve("o/n", "--upload-pack=x")))
            check("git clone url local", get_forge("raw").clone_url("o/n").replace("\\", "/").endswith("srv/git/o/n"))

            # Gitea
            lan = get_forge("lan")
            fake = FakeTransport({
                ("GET", "repos/o/n"): {"default_branch": "main", "private": False, "archived": False},
                ("GET", "repos/o/n/branches/main"): {"commit": {"id": "a" * 40, "timestamp": "2026-10-10"}},
                ("GET", "repos/o/n/contents/SECURITY.md"): {"type": "file", "sha": "b" * 40,
                                                            "content": base64.b64encode(b"hi").decode()},
                ("GET", "repos/o/n/issues"): lambda q: [
                    {"number": 2, "updated_at": "2026-10-02", "pull_request": None},
                    {"number": 1, "updated_at": "2026-10-01", "pull_request": {"merged": False}}]
                    if q.get("page") == "1" else [],
                ("GET", "repos/o/n/issues/1/timeline"): [
                    {"type": "pull_ref", "ref_issue": {"number": 5, "repository": {"full_name": "o/n"}}},
                    {"type": "commit_ref", "ref_commit_sha": "c" * 40}, {"type": "comment"}],
                ("POST", "repos/o/n/issues"): {"number": 9, "html_url": "u9", "created_at": "t"},
                ("PATCH", "repos/o/n/issues/9"): {"number": 9},
            })
            lan.transport = fake
            check("gitea repo", lan.get("repos/o/n")["default_branch"] == "main")
            check("gitea commit via branch", lan.get("repos/o/n/commits/main")["sha"] == "a" * 40)
            check("gitea contents blob", lan.get("repos/o/n/contents/SECURITY.md")["sha"] == "b" * 40)
            check("gitea token header", fake.calls[-1][3].get("Authorization") == "token t-lan")
            items = lan.get_list("repos/o/n/issues?state=all&sort=updated&direction=asc&per_page=100")
            check("gitea list sorted asc", [x["number"] for x in items] == [1, 2])
            check("gitea pull_request only for PRs", "pull_request" not in items[1] and "pull_request" in items[0])
            check("gitea limit param", fake.calls[-1][2].get("limit") == "50" and "per_page" not in fake.calls[-1][2])
            tl = lan.get_list("repos/o/n/issues/1/timeline")
            check("gitea timeline mapped", [e["event"] for e in tl] == ["cross-referenced", "referenced"])
            check("gitea pvr not available", raises(lambda: lan.get("repos/o/n/private-vulnerability-reporting"),
                                                    GhNotFound))
            check("gitea create issue", lan.post("repos/o/n/issues", {"title": "t", "body": "b"})["number"] == 9)
            lan.post("repos/o/n/issues/9", {"state": "closed", "state_reason": "completed"}, method="PATCH")
            check("gitea close drops state_reason", fake.calls[-1][4] == {"state": "closed"})
            check("gitea no confidential", raises(lambda: lan.post("repos/o/n/issues", {"title": "t", "confidential": True})))
            check("gitea permalink", lan.blob_url("o/n", "d" * 40, "a.py", "3-5")
                  == f"http://git.example.net:3000/o/n/src/commit/{'d' * 40}/a.py#L3-L5")

            # GitLab
            corp = get_forge("corp")
            pid = "g%2Fs%2Fn"
            gl = FakeTransport({
                ("GET", f"projects/{pid}"): {"path_with_namespace": "g/s/n", "default_branch": "main",
                                             "visibility": "public", "web_url": "w"},
                ("GET", f"projects/{pid}/repository/files/SECURITY.md"): {"blob_id": "e" * 40, "content": "aGk=",
                                                                          "file_path": "SECURITY.md"},
                ("GET", f"projects/{pid}/issues"): (200, [{"iid": 3, "state": "opened", "title": "x",
                                                           "author": {"username": "anna"}, "labels": ["bug"],
                                                           "web_url": "w3"}], {"X-Next-Page": ""}),
                ("GET", f"projects/{pid}/issues/3"): {"iid": 3, "state": "closed", "web_url": "w3"},
                ("GET", f"projects/{pid}/issues/3/notes"): [
                    {"id": 1, "body": "thanks", "author": {"username": "maint"}},
                    {"id": 2, "system": True, "body": "mentioned in commit " + "f" * 40}],
                ("GET", f"projects/{pid}/issues/3/related_merge_requests"): [
                    {"iid": 7, "references": {"full": "g/s/n!7"}}],
                ("GET", f"projects/{pid}/merge_requests/7"): {"iid": 7, "state": "merged", "merge_commit_sha": "m",
                                                              "target_branch": "main", "author": {"username": "m"}},
                ("GET", f"projects/{pid}/merge_requests/7/diffs"): [{"new_path": "src/a.py"}],
                ("POST", f"projects/{pid}/issues"): lambda q: {"iid": 11, "web_url": "w11",
                                                               "confidential": True, "state": "opened"},
                ("PUT", f"projects/{pid}/issues/3"): {"iid": 3},
            })
            corp.transport = gl
            check("gitlab project mapped", corp.get("repos/g/s/n")["private"] is False)
            check("gitlab contents ref = default branch",
                  corp.get("repos/g/s/n/contents/SECURITY.md")["sha"] == "e" * 40 and gl.calls[-1][2] == {"ref": "main"})
            check("gitlab token header", gl.calls[-1][3].get("PRIVATE-TOKEN") == "t-gl")
            iss = corp.get_list("repos/g/s/n/issues?state=all&sort=created&direction=asc&per_page=100")
            check("gitlab issue mapped", iss[0]["number"] == 3 and iss[0]["state"] == "open"
                  and iss[0]["user"]["login"] == "anna" and iss[0]["labels"] == [{"name": "bug"}]
                  and "pull_request" not in iss[0])
            check("gitlab issue state closed", corp.get("repos/g/s/n/issues/3")["state"] == "closed")
            com = corp.get_list("repos/g/s/n/issues/3/comments")
            check("gitlab notes without system notes", [c["id"] for c in com] == [1] and com[0]["html_url"] == "w3#note_1")
            tl = corp.get_list("repos/g/s/n/issues/3/timeline")
            check("gitlab timeline: MR + commit", [e["event"] for e in tl] == ["cross-referenced", "referenced"]
                  and tl[0]["source"]["issue"]["repository"]["full_name"] == "g/s/n")
            check("gitlab MR mapped", corp.get("repos/g/s/n/pulls/7")["merged"] is True)
            check("gitlab write off by default", raises(lambda: corp.post("repos/g/s/n/issues", {"title": "t"})))
            corp.write = True
            res = corp.post("repos/g/s/n/issues", {"title": "t", "body": "b", "confidential": True})
            check("gitlab confidential issue", res["number"] == 11 and gl.calls[-1][4]["confidential"] is True
                  and gl.calls[-1][4]["description"] == "b")
            corp.post("repos/g/s/n/issues/3", {"state": "closed"}, method="PATCH")
            check("gitlab close via state_event", gl.calls[-1][4] == {"state_event": "close"})
            check("gitlab permalink", corp.blob_url("g/s/n", "1" * 40, "a.py", "3-5").endswith("/-/blob/" + "1" * 40 + "/a.py#L3-5"))
            check("gitlab subgroup path split", HttpForge.split_path("repos/g/s/n/issues/3/comments")[:2]
                  == ("g/s/n", "issues/3/comments"))

            # Errors and redirects
            err_t = FakeTransport({("GET", "repos/o/n"): (403, {"message": "rate"}, {})})
            lan.transport = err_t
            check("403 is an error, not 'not found'", raises(lambda: lan.get("repos/o/n")) and
                  not raises(lambda: lan.get("repos/o/n"), GhNotFound))
            check("403 with forbidden_ok -> GhNotFound", raises(lambda: lan.get("repos/o/n", forbidden_ok=True), GhNotFound))
            h = _SameHostRedirect()
            req = urllib.request.Request("https://a.example/x", headers={"Authorization": "token s"})
            check("redirect to other host refused",
                  raises(lambda: h.redirect_request(req, None, 302, "", {}, "https://b.example/x")))

            # Router
            r = Router({"github": type("G", (), {"get": lambda s, p, forbidden_ok=False: ("gh", p),
                                                 "get_list": lambda s, p, m=1000, forbidden_ok=False: []})(),
                        "corp": corp})
            check("router default github", r.get("repos/o/n") == ("gh", "repos/o/n"))
            check("router alias", r.get("repos/corp:g/s/n")["full_name"] == "g/s/n")

            # disclosure_watch: a register entry on a forge goes through the forge's paths
            import disclosure_watch as dw
            entry = {"id": "x-01", "channel": "issue", "repo": "g/s/n", "forge": "corp", "reference": "3",
                     "last_checked": None, "draft": ""}
            w = dw.Watcher(r, {"own_accounts": []}, [entry], {"repos": {}})
            res = w.check_issue(entry)
            check("watch: forge entry read via the forge", res["repo"] == "corp:g/s/n" and res["state"] == "closed"
                  and res["comments_foreign"] == 1)
            check("watch: MR link qualified with the alias",
                  any(d.get("kind") == "pr" and d.get("repo") == "corp:g/s/n" and d.get("merged") for d in res["links"]))
            check("watch: commit URL on the forge",
                  any(d.get("kind") == "commit" and d["url"].startswith("https://gitlab.example.org/g/s/n/-/commit/")
                      for d in res["links"]))
            check("watch: repo list uses qualified keys", "corp:g/s/n" in dw.repo_list({}, [entry], {}))
            # own_repos_check: own public repository on GitLab, SECURITY.md without a channel -> gap
            import own_repos_check as orc
            gl.routes[("GET", f"projects/{pid}/repository/files/SECURITY.md")] = {
                "blob_id": "e" * 40, "content": base64.b64encode(b"Report security issues here.").decode()}
            rc = orc.check({"full_name": "g/s/n", "default_branch": "main", "fork": False}, corp)
            check("own repo on GitLab: gap without channel", rc["repo"] == "corp:g/s/n" and rc["pvr"] is False
                  and any("confidential channel" in g for g in rc["gaps"]))
            gl.routes[("GET", f"projects/{pid}/repository/files/SECURITY.md")] = {
                "blob_id": "e" * 40, "content": base64.b64encode(b"Open a confidential issue.").decode()}
            check("own repo on GitLab: confidential issue is a channel",
                  orc.check({"full_name": "g/s/n", "default_branch": "main", "fork": False}, corp)["gaps"] == [])
            pub = dw.public_only({"entries": [], "status_changes": [], "deadlines": [], "repos": [],
                                  "own_repos": [{"repo": "corp:g/s/n", "private": True, "items": [], "security": []}],
                                  "errors": ["corp:g/s/n: HTTP 500 secret detail", "mailbox: LoginError: x",
                                             "acme/tool: rate limit"]})
            check("watch: forge repo error and mailbox error stay out of the public report",
                  pub["errors"] == ["acme/tool: rate limit"])
            import register as reg
            probs = reg.check([{"id": "x-01", "repo": "g/s/n", "forge": "corp", "finding": "f",
                                "severity_class": "critical", "channel": "issue", "status": "open"}])
            check("register check accepts a GitLab subgroup on a forge", not any("valid" in p for p in probs))
            probs = reg.check([{"id": "x-02", "repo": "g/s/n", "finding": "f",
                                "severity_class": "critical", "channel": "issue", "status": "open"}])
            check("register check still refuses a subgroup on github.com", any("valid" in p for p in probs))
            check("watch: upstream row with alias", dw.UPSTREAM_LINE.search("| Upstream | `corp:g/s/n` |").group(1)
                  == "corp:g/s/n")
        ok_s, total_s = _self_test_submit()
        ok, total = ok + ok_s, total + total_s
    finally:
        _common.ENV_FILE = saved_file
        _CACHE.clear()
        os.environ.update(saved_env)
    out(f"forge self-test: {ok}/{total} OK")
    return 0 if ok == total else 1


def _self_test_submit():
    """End to end without network: critical finding as a confidential GitLab issue
    (dry run, approval, submission, confidential register) and the refusals around it."""
    import tempfile

    import _submit
    import approval
    import forge as mod        # the module issue_submit uses (this file may run as __main__)
    import issue_submit

    ok, total = 0, 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {name}")

    names = ("ROOT", "PRIVATE", "APPROVALS", "CHECKS", "REGISTER", "REGISTER_PRIVATE", "REGISTER_README",
             "REGISTER_README_PRIVATE", "ENV_FILE")
    saved = {n: getattr(_common, n) for n in names}
    saved_fetch = _submit.FETCH_BLOB
    switches = ("disclosure_codex_check", "claudex_finding_check", "claudex_exposure_check")
    saved_sw = {k: os.environ.pop(k, None) for k in switches}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _common.ROOT, _common.PRIVATE = root, root / "private"
        _common.APPROVALS = root / "private" / "disclosures" / "approvals"
        _common.CHECKS = root / "private" / "disclosures" / "checks"
        _common.REGISTER = root / "disclosures" / "register.json"
        _common.REGISTER_PRIVATE = root / "private" / "disclosures" / "register.json"
        _common.REGISTER_README = root / "disclosures" / "README.md"
        _common.REGISTER_README_PRIVATE = root / "private" / "disclosures" / "README.md"
        _common.ENV_FILE = root / ".env"
        _common.write_text(_common.ENV_FILE, "forge_corp_type=gitlab\nforge_corp_url=https://gitlab.example.org\n"
                                             "forge_corp_token=t\nforge_corp_write=on\n"
                                             "forge_lan_type=gitea\nforge_lan_url=https://git.example.net\n"
                                             "forge_lan_write=on\n")
        _submit.FETCH_BLOB = lambda repo, path: None          # upstream has no SECURITY.md
        mod._CACHE.clear()
        try:
            pid = "g%2Fs%2Fn"
            fake = FakeTransport({
                ("GET", "user"): {"username": "me"},
                ("POST", f"projects/{pid}/issues"): lambda q: {"iid": 21, "web_url": "https://gitlab.example.org/g/s/n/-/issues/21",
                                                               "confidential": True, "state": "opened",
                                                               "created_at": "2026-10-10T20:00:00Z"},
            })
            mod.get_forge("corp").transport = fake
            pol = {"blob_sha": None, "checked_at": "2026-10-10", "versions": "all", "channel": "no policy",
                   "scope": "in scope", "deadlines": "none", "required_content": {}, "response_days": None,
                   "result": "report"}
            meta = {"id": "selftest-gl", "channel": "issue", "forge": "corp", "repo": "g/s/n",
                    "title": "Path traversal in export", "finding": "f", "severity_class": "critical",
                    "severity_reason": "write outside the target", "upstream_ref": "main@" + "e" * 40,
                    "confidential": True, "policy": pol}

            def draft(where, m):
                p = root / where / "d.md"
                _common.write_text(p, "# internal\n\n```json disclosure\n" + json.dumps(m, indent=2)
                                   + "\n```\n\n<!-- TEXT -->\n**Summary**\n\nThe export joins a user path. PoC below.\n")
                return p

            outside = draft("drafts", meta)
            check("confidential draft outside private/ refused", issue_submit.main([str(outside)]) == 2)
            p = draft("private/repos/x", meta)
            check("dry run confidential issue green (exploit words allowed)", issue_submit.main([str(p)]) == 0)
            check("submit without approval refused", issue_submit.main([str(p), "--submit"]) == 2)
            check("grant", approval.main(["grant", str(p), "--action", "issue", "--note", "t"]) == 0)
            check("submit", issue_submit.main([str(p), "--submit"]) == 0)
            sent = [c for c in fake.calls if c[0] == "POST"]
            check("posted as confidential", sent and sent[-1][4].get("confidential") is True)
            # stored with its record "x" (the draft lies in private/repos/x/disclosures/), confidential part
            rec_priv = root / "private" / "repos" / "x" / "disclosures" / "register.json"
            reg_priv = _common.load_json(rec_priv, [])
            check("entry in the record's confidential register only",
                  [e["id"] for e in reg_priv] == ["selftest-gl"] and not _common.load_json(_common.REGISTER, [])
                  and not _common.load_json(_common.REGISTER_PRIVATE, [])
                  and not (root / "repos" / "x" / "disclosures" / "register.json").exists()
                  and reg_priv[0].get("forge") == "corp" and reg_priv[0].get("confidential") is True
                  and reg_priv[0].get("record") == "x" and reg_priv[0]["reference"] == "21")
            check("record overview written next to it, root overview without the entry",
                  (root / "private" / "repos" / "x" / "disclosures" / "REGISTER.md").exists()
                  and "selftest-gl" not in (_common.REGISTER.parent / "README.md").read_text(encoding="utf-8"))
            check("approval was stored with the record and is consumed",
                  not list((root / "private").rglob("selftest-gl.approval")))
            p2 = draft("private/repos/y", {**meta, "id": "selftest-gt", "forge": "lan", "repo": "o/n"})
            check("Gitea: confidential refused", issue_submit.main([str(p2)]) == 2)
            p4 = draft("private/repos/e", {**meta, "id": "selftest-ex", "exposure": "<network|local>"})
            check("unfilled exposure placeholder refused", issue_submit.main([str(p4)]) == 2)
            p5 = draft("private/repos/c", {**meta, "id": "selftest-cf", "confidential": "yes"})
            check("confidential must be a boolean", issue_submit.main([str(p5)]) == 2)
            p3 = draft("private/repos/z", {**meta, "id": "selftest-pub", "confidential": False})
            check("critical public issue without critical_public refused", issue_submit.main([str(p3)]) == 2)
        finally:
            for n, v in saved.items():
                setattr(_common, n, v)
            _submit.FETCH_BLOB = saved_fetch
            for k, v in saved_sw.items():
                if v is not None:
                    os.environ[k] = v
            mod._CACHE.clear()
    return ok, total


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Configured code hosts (forges)")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list")
    c = sub.add_parser("check")
    c.add_argument("alias")
    c.add_argument("--repo")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    try:
        if a.cmd == "list":
            return cmd_list()
        if a.cmd == "check":
            return cmd_check(a.alias, a.repo)
        ap.print_help()
        return 2
    except GhNotFound as exc:
        err(f"ERROR: not found: {exc}")
        return 1
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
