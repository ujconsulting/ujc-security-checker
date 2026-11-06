#!/usr/bin/env python3
"""Quarantine clone of a reviewed repository on a fixed commit (rule 2 of CLAUDE.md).

Source - any of:

    owner/name                    github.com
    <alias>:owner/name            forge from the .env (GitHub Enterprise/own GitHub server,
                                  Gitea/Forgejo, GitLab incl. subgroups, plain git server)
    https://... | ssh://... | git@host:path    any git URL
    <drive>:/path/to/repo | /srv/git/x.git | file://...   local repository (also a bare one)

    python tools/quarantine_clone.py <source> <name> --ref <sha|tag|branch>
    python tools/quarantine_clone.py --self-test        # local temp repositories only

What it enforces:
- target is quarantine/<name>/ (gitignored), never anything else; it must not exist yet
- no submodules, no LFS smudge, no checkout before the commit is fixed; then
  `checkout --detach <sha>`; core.autocrlf=false, core.symlinks=false, hooksPath disabled
- local sources are cloned with --no-local (real transport, no hard links into a foreign
  object store), protocol.ext disabled, object checks on (transfer.fsckObjects)
- a forge token goes as an http.<base>.extraHeader through GIT_CONFIG_* environment
  variables - never on the command line, never in the clone's .git/config, never to another host
- no git configuration of the user or the system is read (GIT_CONFIG_NOSYSTEM, own HOME),
  so no credential helper, alias or url.insteadOf rewrites a source

The result (source, commit, time) goes to .claudex-tmp/<name>/clone.json. Nothing from the
repository is executed. Exit 0 ok, 1 git failed, 2 operator error.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "disclosures"))
import _common  # noqa: E402
import forge as forges  # noqa: E402
from _common import DisclosureError, err, now_iso, out, write_json  # noqa: E402

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
# A ref never starts with '-' (it would be read as an option, e.g. --upload-pack=...), no '..'
REF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,199}$")
CLONE_SAFE = ["-c", "core.autocrlf=false", "-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null",
              "-c", "submodule.recurse=false", "-c", "fetch.recurseSubmodules=false",
              "-c", "protocol.ext.allow=never", "-c", "transfer.fsckObjects=true",
              "-c", "fetch.fsckObjects=true", "-c", "core.fsmonitor=false"]


def is_local(source: str) -> bool:
    return source.startswith("file://") or bool(re.match(r"^([A-Za-z]:[\\/]|/|\\\\|\.\.?[\\/])", source))


def is_url(source: str) -> bool:
    return bool(re.match(r"^(https?|ssh|git)://", source)) or bool(re.match(r"^[\w.-]+@[\w.-]+:", source))


def resolve_source(source: str):
    """(clone_url, forge or None, description)."""
    if is_local(source):
        p = source[len("file://"):] if source.startswith("file://") else source
        if not Path(p).exists():
            raise DisclosureError(f"local source does not exist: {p}")
        return str(Path(p).resolve()), None, "local path"
    if is_url(source):
        for alias in forges.configured():
            f = forges.get_forge(alias)
            if f.web and source.startswith(f.web + "/"):
                return source, f, f"URL on forge {alias}"
        return source, None, "URL (no forge configured - anonymous)"
    f, repo = forges.resolve(source)
    return f.clone_url(repo), f, f"{f.alias}:{repo} ({f.kind})"


def auth_env(f, url: str) -> dict:
    """GIT_CONFIG_* entries with an extraHeader for exactly the forge's base URL."""
    if f is None or not url.startswith(("http://", "https://")) or not f.cfg.get("token"):
        return {}
    if url.startswith("http://") and str(f.cfg.get("allow_http", "off")).lower() not in forges.ON:
        raise DisclosureError(f"forge {f.alias}: plain http refused for a token (forge_{f.alias}_allow_http)")
    token = forges._resolve_token(f.alias, f.cfg["token"])
    user = f.cfg.get("user") or {"gitlab": "oauth2", "github": "x-access-token"}.get(f.kind, "token")
    basic = base64.b64encode(f"{user}:{token}".encode()).decode("ascii")
    u = urlsplit(f.web)
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"http.{u.scheme}://{u.netloc}/.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}"}


def run_git(args, cwd=None, env=None):
    r = subprocess.run(["git", *CLONE_SAFE, *args], cwd=cwd, env=env, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=3600)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _remove_tree(path: Path) -> None:
    """rmtree that also removes read-only git objects (Windows)."""
    def retry(func, p, _exc):
        os.chmod(p, 0o700)
        func(p)
    if path.exists():
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=retry)
        else:
            shutil.rmtree(path, onerror=retry)


def clone(source: str, name: str, ref: str, root: Path = None) -> dict:
    root = root or _common.ROOT
    if not NAME_RE.match(name or ""):
        raise DisclosureError(f"name {name!r}: lower case, digits, . _ - (max 64)")
    if not ref:
        raise DisclosureError("--ref is required (commit SHA, tag or branch) - quarantine is on a fixed commit")
    if not REF_RE.match(ref) or ".." in ref or ref.endswith((".lock", "/")):
        raise DisclosureError(f"--ref {ref!r}: not a plain commit SHA, tag or branch name")
    target = root / "quarantine" / name
    if target.exists():
        raise DisclosureError(f"{target.relative_to(root).as_posix()} exists - remove it or choose another name")
    url, f, desc = resolve_source(source)
    home = Path(tempfile.mkdtemp(prefix="ujc-git-home-"))
    try:
        env = forges.git_env({"HOME": str(home), "XDG_CONFIG_HOME": str(home), "USERPROFILE": str(home),
                              **auth_env(f, url)})
        target.parent.mkdir(parents=True, exist_ok=True)
        args = ["clone", "--no-checkout", "--no-recurse-submodules", "--origin", "origin"]
        if is_local(source):
            args.append("--no-local")
        rc, _o, e = run_git([*args, "--", url, str(target)], env=env)
        if rc != 0:
            raise RuntimeError(f"git clone failed: {e[-400:]}")
        rc, sha, e = run_git(["-C", str(target), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], env=env)
        if rc != 0 and not SHA40.match(ref):
            rc, sha, e = run_git(["-C", str(target), "rev-parse", "--verify", "--quiet",
                                  f"origin/{ref}^{{commit}}"], env=env)
        if rc != 0:
            # a commit outside the advertised refs: fetch it explicitly
            rc2, _o, e2 = run_git(["-C", str(target), "fetch", "--no-tags", "--no-recurse-submodules",
                                   "origin", ref], env=env)
            rc, sha, e = run_git(["-C", str(target), "rev-parse", "--verify", "--quiet", "FETCH_HEAD^{commit}"],
                                 env=env) if rc2 == 0 else (rc2, "", e2)
        if rc != 0 or not SHA40.match(sha):
            raise RuntimeError(f"ref {ref!r} not found: {e[-300:]}")
        rc, _o, e = run_git(["-C", str(target), "-c", "advice.detachedHead=false", "checkout", "--detach", sha],
                            env=env)
        if rc != 0:
            raise RuntimeError(f"checkout {sha[:12]} failed: {e[-300:]}")
        for k, v in (("core.autocrlf", "false"), ("core.symlinks", "false"), ("core.hooksPath", "/dev/null"),
                     ("submodule.recurse", "false"), ("core.trustctime", "false")):
            run_git(["-C", str(target), "config", k, v], env=env)
        submodules = (target / ".gitmodules").exists()
        lfs = any("filter=lfs" in p.read_text(encoding="utf-8", errors="replace")
                  for p in target.rglob(".gitattributes") if ".git" not in p.parts)
    except RuntimeError as exc:
        _remove_tree(target)
        raise DisclosureError(str(exc)) from exc
    finally:
        shutil.rmtree(home, ignore_errors=True)
    # the URL never carries the token (it travels only in the GIT_CONFIG_* environment)
    info = {"name": name, "source": source, "clone_url": url, "kind": desc, "ref": ref, "commit": sha,
            "forge": f.alias if f else None, "submodules_present": submodules, "lfs_present": lfs,
            "cloned_at": now_iso(), "path": f"quarantine/{name}"}
    write_json(root / ".claudex-tmp" / name / "clone.json", info)
    return info


def self_test() -> int:
    ok, total = 0, 0

    def check(label, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            out(f"ERROR: self-test {label}")

    def g(*args, cwd):
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                       env=forges.git_env({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
                                           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}))

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src = td / "src"
        src.mkdir()
        g("init", "-q", "-b", "main", cwd=src)
        (src / "a.txt").write_bytes(b"one\r\n")
        (src / ".gitmodules").write_text("[submodule \"x\"]\n\tpath = x\n\turl = https://example.org/x\n")
        g("add", "a.txt", ".gitmodules", cwd=src)
        g("commit", "-q", "-m", "c1", cwd=src)
        first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src, capture_output=True, text=True).stdout.strip()
        (src / "a.txt").write_bytes(b"two\n")
        g("commit", "-q", "-am", "c2", cwd=src)
        g("tag", "v1", cwd=src)
        root = td / "checker"
        root.mkdir()
        try:
            info = clone(str(src), "tool", first, root)
            q = root / "quarantine" / "tool"
            check("clone on the fixed commit", info["commit"] == first)
            check("bytes unchanged (autocrlf off)", (q / "a.txt").read_bytes() == b"one\r\n")
            check("detached HEAD", subprocess.run(["git", "-C", str(q), "symbolic-ref", "-q", "HEAD"],
                                                  capture_output=True).returncode != 0)
            check("submodules reported, not cloned", info["submodules_present"] and not (q / "x").exists())
            check("record written", (root / ".claudex-tmp" / "tool" / "clone.json").is_file())
            cfg = (q / ".git" / "config").read_text()
            check("hooks disabled in the clone", "hooksPath = /dev/null" in cfg)
            check("no header in the clone config", "extraHeader" not in cfg)
            check("existing target refused", _raises(lambda: clone(str(src), "tool", first, root)))
            check("tag as ref", clone(str(src), "tool2", "v1", root)["commit"] != first)
            check("unknown ref refused and cleaned up",
                  _raises(lambda: clone(str(src), "tool3", "nope", root)) and not (root / "quarantine" / "tool3").exists())
            check("bad name refused", _raises(lambda: clone(str(src), "../x", first, root)))
            check("missing ref refused", _raises(lambda: clone(str(src), "tool4", "", root)))
            check("option-like ref refused", _raises(lambda: clone(str(src), "tool5", "--upload-pack=x", root))
                  and not (root / "quarantine" / "tool5").exists())
            check("ref with .. refused", _raises(lambda: clone(str(src), "tool6", "main..v1", root)))
        except DisclosureError as exc:
            check(f"clone raised {exc}", False)

        # forge type git: SECURITY.md and blob SHA via the bare cache
        saved_root, saved_env = _common.ROOT, _common.ENV_FILE
        try:
            _common.ROOT = root
            _common.ENV_FILE = root / ".env"
            (src / "SECURITY.md").write_bytes(b"mail us\n")
            g("add", "SECURITY.md", cwd=src)
            g("commit", "-q", "-m", "c3", cwd=src)
            base = td.as_posix()
            _common.ENV_FILE.write_text(f"forge_raw_type=git\nforge_raw_url={base}\n")
            forges._CACHE.clear()
            fg = forges.get_forge("raw")
            check("git forge from .env", fg.kind == "git" and not fg.write
                  and Path(fg.clone_url("o/src")) == Path(base) / "o" / "src")
            fg2 = forges.GitForge("raw", {"url": str(td)})
            fg2.clone_url = lambda repo: str(src)
            meta = fg2.get("repos/o/src")
            check("git forge default branch", meta["default_branch"] == "main")
            d = fg2.get("repos/o/src/contents/SECURITY.md")
            want = subprocess.run(["git", "rev-parse", "HEAD:SECURITY.md"], cwd=src, capture_output=True,
                                  text=True).stdout.strip()
            check("git forge blob SHA", d["sha"] == want)
            content = base64.b64decode(d["content"])
            check(f"git forge content {content!r}", content == b"mail us\n")
            check("git forge has no issues", _raises(lambda: fg2.get_list("repos/o/src/issues"), _common.GhNotFound))
        finally:
            _common.ROOT, _common.ENV_FILE = saved_root, saved_env
            forges._CACHE.clear()
    check("token header only for the forge host",
          auth_env(None, "https://x/y") == {})
    f = forges.GitLabForge("t", {"url": "https://gitlab.example.org", "token": "abc"})
    env = auth_env(f, "https://gitlab.example.org/g/n.git")
    check("extraHeader scoped to the base URL", env.get("GIT_CONFIG_KEY_0") == "http.https://gitlab.example.org/.extraHeader"
          and base64.b64decode(env["GIT_CONFIG_VALUE_0"].split()[-1]) == b"oauth2:abc")
    out(f"quarantine_clone self-test: {ok}/{total} OK")
    return 0 if ok == total else 1


def _raises(fn, exc=DisclosureError) -> bool:
    try:
        fn()
    except exc:
        return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Quarantine clone on a fixed commit")
    ap.add_argument("source", nargs="?")
    ap.add_argument("name", nargs="?")
    ap.add_argument("--ref", default="")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.source or not a.name:
        ap.print_help()
        return 2
    try:
        info = clone(a.source, a.name, a.ref)
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 1 if "failed" in str(exc) or "not found" in str(exc) else 2
    out(f"OK: {info['path']} on {info['commit']} ({info['kind']})")
    if info["submodules_present"]:
        out("NOTE: .gitmodules present - submodules NOT cloned; review them as separate sources")
    if info["lfs_present"]:
        out("NOTE: LFS attributes present - LFS objects NOT downloaded (pointer files only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
