#!/usr/bin/env python3
"""Check own public GitHub repositories for a working disclosure channel.

Towards GitHub it only reads (GET). Locally it writes exactly one file: the Markdown
overview (--out, default disclosures/own_repos.md, overwritten on every run).

Rule ("when an own repository goes public"):
first enable private vulnerability reporting, THEN a SECURITY.md that points exactly
to it, plus a reachable address. A SECURITY.md that forbids the public issue but
names no open channel is worse than none.
Forks need no SECURITY.md (reports go upstream).

Per public repository of the accounts (default: own_accounts from watch_config,
extended by private/disclosures/watch_config.local.json):
- fork yes/no, archived
- PVR on/off      (GET repos/<o>/<r>/private-vulnerability-reporting)
- SECURITY.md     (root, .github/, docs/) - present, named addresses,
                  names PVR, forbids public issue
- gaps: no PVR; no SECURITY.md; SECURITY.md does not point to PVR;
  SECURITY.md blocks issues without an open channel
  (no mail address is required: public files name none, PVR is the channel)

Nothing is enabled, committed or changed on GitHub - those are steps on instruction.

    python tools/disclosures/own_repos_check.py
    python tools/disclosures/own_repos_check.py --accounts ujconsulting --out disclosures/own_repos.md

Exit 0 no gaps, 1 gaps, 2 error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (DISCLOSURES, ROOT, DisclosureError, GhNotFound, err,  # noqa: E402
                     gh_get, gh_get_list, gh_logged_in, load_watch_config, now_iso, out, write_text)
import channel  # noqa: E402
import forge as forges  # noqa: E402
from channel import SECURITY_PATHS, evaluate_security, read_file  # noqa: E402

def check(repo_info, f=None):
    """f = forge (forge.py); None = github.com. On Gitea/GitLab there is no PVR: the SECURITY.md
    must name a working channel itself (address; on GitLab also a confidential issue)."""
    name = repo_info["full_name"]
    github = f is None or f.alias == forges.DEFAULT_ALIAS
    res = {"repo": name if github else forges.qualified(name, f.alias), "fork": repo_info.get("fork"),
           "archived": repo_info.get("archived"), "default": repo_info.get("default_branch"), "gaps": [],
           "url": repo_info.get("html_url") or f"https://github.com/{name}", "kind": "github" if github else f.kind}
    try:
        if github:
            res["pvr"] = bool((gh_get(f"repos/{name}/private-vulnerability-reporting",
                                      forbidden_ok=True) or {}).get("enabled"))   # 403: shown as a gap
        else:
            res["pvr"] = bool((f.get(f"repos/{name}/private-vulnerability-reporting",
                                     forbidden_ok=True) or {}).get("enabled"))
    except GhNotFound:
        res["pvr"] = None if github or "pvr" in f.features else False
    res["security"] = None
    channel._FORGE = None if github else f
    try:
        for p in SECURITY_PATHS:
            text, _ = read_file(name, p, res["default"])
            if text is not None:
                ev = evaluate_security(text)
                res["security"] = {"path": p, **ev,
                                   "confidential_issue": bool(re.search(r"confidential issue", text, re.I))}
                break
    finally:
        channel._FORGE = None
    if res["fork"]:
        return res                         # forks: reports go upstream
    if not github and "pvr" not in f.features:
        s = res["security"]
        if s is None:
            res["gaps"].append("no SECURITY.md")
        elif not s["addresses"] and not (s["confidential_issue"] and "confidential_issue" in f.features):
            res["gaps"].append(f"SECURITY.md names no confidential channel ({f.kind} has no PVR: "
                               "address" + (" or confidential issue" if "confidential_issue" in f.features else "") + ")")
        return res
    if res["pvr"] is not True:
        res["gaps"].append("PVR off" if res["pvr"] is False else "PVR status not readable")
    s = res["security"]
    if s is None:
        res["gaps"].append("no SECURITY.md")
    else:
        if "advisory" not in s["channels"]:
            res["gaps"].append("SECURITY.md does not point to PVR")
        if s["forbids_public_issue"] and not s["addresses"] and res["pvr"] is not True:
            res["gaps"].append("SECURITY.md blocks issues without an open channel (Hermes-iOS case)")
    return res


def as_markdown(results, accounts) -> str:
    z = ["# Own public repositories - disclosure channel", "",
         f"As of: {now_iso()}, accounts: {', '.join(accounts)}. Generated with "
         "`python tools/disclosures/own_repos_check.py` (reads GitHub only).", "",
         "Rule: first enable PVR, then `SECURITY.md` from `templates/SECURITY.md` "
         "(skill `finding-disclosure`, section \"Own public repositories\"). Forks need none.", "",
         "| Repo | Fork | Archived | PVR | SECURITY.md | Mail addresses (count) | Gaps |", "|---|---|---|---|---|---|---|"]
    for e in results:
        s = e["security"]
        z.append("| " + " | ".join([
            f"[{e['repo']}]({e.get('url') or 'https://github.com/' + e['repo']})", "yes" if e["fork"] else "no",
            "yes" if e["archived"] else "no",
            {True: "on", False: "off", None: "?"}[e["pvr"]] if e.get("kind", "github") == "github"
            else f"- ({e['kind']})",
            f"`{s['path']}`" if s else "-",
            # count only - the report is public and must not repeat mail addresses
            str(len(s["addresses"])) if s and s["addresses"] else "-",
            "; ".join(e["gaps"]) or ("- (fork)" if e["fork"] else "none")]) + " |")
    gaps = sum(1 for e in results if e["gaps"])
    z += ["", f"Repositories with gaps: {gaps} of {len(results)}."]
    return "\n".join(z)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Disclosure channel of own public repositories (reads GitHub, writes --out)")
    ap.add_argument("--accounts", nargs="+", default=None,
                    help="default: own_accounts from watch_config (+ private/disclosures/watch_config.local.json); "
                         "<alias>:<account> for an account on a forge from the .env")
    ap.add_argument("--out", default=str(DISCLOSURES / "own_repos.md"),
                    help="the one file this tool writes (Markdown overview)")
    a = ap.parse_args(argv)
    try:
        gh_logged_in()
        results = []
        a.accounts = a.accounts or load_watch_config().get("own_accounts") or []
        found = []
        for account in a.accounts:
            alias, _, login = account.rpartition(":")
            f = None if alias in ("", forges.DEFAULT_ALIAS) else forges.get_forge(alias)
            try:
                if f is None:
                    items = gh_get_list(f"users/{login}/repos?type=owner&per_page=100", 500)
                else:
                    items = f.get_list(f"users/{login}/repos?type=owner&per_page=100", 500)
            except GhNotFound:
                out(f"WARNING: account {account} not found (HTTP 404) - skipped")
                continue
            found.append(account)
            for r in items:
                if r.get("private") or r.get("visibility", "public") != "public":
                    continue
                results.append(check(r, f))
    except DisclosureError as exc:
        err(f"ERROR: {exc}")
        return 2
    results.sort(key=lambda e: e["repo"].lower())
    target = Path(a.out)
    write_text(target, as_markdown(results, found))
    for e in results:
        out(f"{e['repo']:<50} fork={'y' if e['fork'] else 'n'} pvr={e['pvr']} "
            f"security={'y' if e['security'] else 'n'} gaps: {'; '.join(e['gaps']) or '-'}")
    gaps = sum(1 for e in results if e["gaps"])
    try:
        shown = target.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        shown = str(target)
    out(f"{len(results)} public repositories, {gaps} with gaps -> {shown}")
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
