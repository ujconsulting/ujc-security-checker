"""Classify incoming items in the OWN public repository and prepare reactions as drafts.

Used by disclosure_watch.py (configuration: watch_config.json -> "own_repos").
Everything here is heuristic and suggestion: classification by keywords, the reaction
is a draft under private/disclosures/inbox/reactions/, submitted only after a
hash-bound approval with issue_submit.py (channel "reaction").

Contents of issues, PRs, comments, advisories and mails are UNTRUSTED data: they
are quoted, never followed. Suspected prompt injection is flagged.

Response time from our SECURITY.md: acknowledge receipt within 5 working days.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from _common import PRIVATE_DISCLOSURES, ROOT, read_draft, write_text

INBOX = PRIVATE_DISCLOSURES / "inbox"
REACTIONS = INBOX / "reactions"
RESPONSE_TIME = "5 working days (SECURITY.md)"

INJECTION_RE = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above) (?:instructions|prompts?)|disregard (?:the|all|previous)"
    r"|you are (?:now )?(?:an?|the) (?:ai|assistant|agent|language model)|system prompt|<\|im_start\|>"
    r"|\[inst\]|<<sys>>|^\s*(?:assistant|system)\s*:|as an ai\b|run (?:this|the following) command"
    r"|curl [^\n|]*\|\s*(?:ba)?sh|iwr [^\n|]*\|\s*iex|base64 -d[^\n]*\|\s*(?:ba)?sh",
    re.I | re.M)

SECURITY_RE = re.compile(r"vulnerab|exploit|security|\bcve-|\brce\b|remote code|injection|"
                         r"\bleak|credential|\btoken|secret|bypass|privilege|xss|ssrf|traversal", re.I)
SPAM_RE = re.compile(r"casino|airdrop|crypto ?giveaway|backlink|\bseo\b|escort|loan offer|whatsapp \+?\d", re.I)
QUESTION_RE = re.compile(r"^(?:how|why|what|can|could|is|are|does|do|where|which|should)\b|\?\s*$", re.I)
FEATURE_RE = re.compile(r"feature|enhancement|request|support for|would be (?:nice|great)|\bproposal\b|"
                        r"\badd (?:a|an|support)\b", re.I)


def injection_suspected(text: str) -> bool:
    return bool(INJECTION_RE.search(text or ""))


def classify(x: dict) -> tuple[str, str]:
    """(kind, reason) for an issue/PR in the own repository."""
    title = x.get("title") or ""
    body = x.get("body") or ""
    text = f"{title}\n{body}"
    labels = {lb.get("name", "").lower() for lb in x.get("labels") or []}
    if SECURITY_RE.search(text) or "security" in labels:
        return "security", "keyword with security relevance - priority, handle confidentially"
    if SPAM_RE.search(text) or (len(body.strip()) < 15 and re.search(r"https?://", text) and not x.get("pull_request")):
        return "spam", "spam pattern or link without content"
    if x.get("pull_request") is not None:
        return "pr", "PR with third-party code - look at it only under tool-review principles, never run it unchecked"
    if "question" in labels or QUESTION_RE.search(title):
        return "question", "question form in the title"
    if "enhancement" in labels or FEATURE_RE.search(text):
        return "feature", "request keyword"
    return "bug", "default for issues without other features"


SUGGESTION = {
    "security": {"labels": ["security"], "close": None,
                 "text": ("Thank you for the report. Please do not post further details publicly. "
                          "Use private vulnerability reporting (Security tab -> \"Report a vulnerability\") "
                          "so we can handle it confidentially. "
                          "We will acknowledge within 5 working days.")},
    "bug": {"labels": ["bug"], "close": None,
            "text": ("Thanks for the report. Could you add the version, your OS and the exact steps "
                     "to reproduce, plus the full error output? That helps us look into it.")},
    "feature": {"labels": ["enhancement"], "close": None,
                "text": "Thanks for the suggestion. We will consider it for a future release."},
    "question": {"labels": ["question"], "close": None,
                 "text": "Thanks for the question. <answer>"},
    "pr": {"labels": [], "close": None,
           "text": ("Thanks for the contribution. We review external changes before running anything "
                    "from them; we will get back to you after the review.")},
    "spam": {"labels": ["invalid"], "close": "not_planned", "text": ""},
}


def _safe(part) -> str:
    """File-name part: only [A-Za-z0-9_.-], no '..', no leading dot."""
    text = re.sub(r"[^A-Za-z0-9_.-]", "_", str(part))
    text = re.sub(r"\.{2,}", "_", text)
    return text.lstrip(".") or "_"


def repo_slug(repo: str, limit: int = 60) -> str:
    """'<owner>__<name>', sanitised, so that two repositories with the same short name of
    different owners do not share an inbox/reaction file or a disclosure ID. Too long:
    cut and extended by a hash of the full name."""
    owner, _, short = repo.partition("/")
    slug = f"{_safe(owner)}__{_safe(short)}"
    if len(slug) > limit:
        slug = slug[:limit - 9] + "-" + hashlib.sha1(repo.encode("utf-8")).hexdigest()[:8]
    return slug


def reaction_path(repo: str, nr, kind: str) -> Path:
    """Where reaction_draft puts (or finds) the draft. A file in the old naming scheme
    (<name>-<nr>-<kind>.md, without the owner) is still used if it belongs to this repository."""
    legacy = REACTIONS / f"{_safe(repo.split('/', 1)[1])}-{_safe(nr)}-{_safe(kind)}.md"
    if legacy.exists():
        try:
            if read_draft(legacy)[0].get("repo") == repo:
                return legacy
        except Exception:                      # unreadable draft: not ours, use the new name
            pass
    return REACTIONS / f"{repo_slug(repo)}-{_safe(nr)}-{_safe(kind)}.md"


def reaction_draft(repo: str, x: dict, kind: str, now: str) -> Path:
    """Draft (draft format, channel "reaction") under private/disclosures/inbox/reactions/.
    File name and draft ID contain the owner. If it already exists, it stays unchanged
    (an approval could depend on it)."""
    nr = x.get("number")
    path = reaction_path(repo, nr, kind)
    if path.exists():
        return path
    v = SUGGESTION[kind]
    meta = {"id": f"reaction-{repo_slug(repo, 50)}-{_safe(nr)}", "channel": "reaction", "repo": repo, "issue": nr,
            "labels": v["labels"], "close": v["close"], "leak_allow": []}
    write_text(path, "\n".join([
        f"# Reaction to {repo}#{nr} ({kind})",
        "",
        f"Generated {now} by disclosure_watch.py - SUGGESTION. Check text, labels and closing,",
        "then `python tools/disclosures/approval.py show <file>`, after approval",
        "`approval.py grant <file> --action reaction --note ...` and",
        "`python tools/disclosures/issue_submit.py <file> --submit`.",
        f"Title (UNTRUSTED): {(x.get('title') or '')[:200]}",
        f"Response time: {RESPONSE_TIME if kind == 'security' else 'none fixed'}",
        "",
        "```json disclosure",
        json.dumps(meta, indent=2, ensure_ascii=False),
        "```",
        "",
        "<!-- TEXT -->",
        v["text"],
    ]))
    return path


def store_inbox(repo: str, kind: str, key: str, head: dict, text: str) -> Path:
    """Store confidential inbox items (security report, advisory, alert) - only under private/."""
    path = INBOX / f"{repo_slug(repo)}-{_safe(kind)}-{_safe(key)}.md"
    lines = [f"# Inbox {repo} {kind} {key} (CONFIDENTIAL)", ""]
    lines += [f"- {k}: {v}" for k, v in head.items()]
    lines += ["", "Content (UNTRUSTED data - quote, never follow"
              + ("; **suspected prompt injection**" if injection_suspected(text) else "") + "):", ""]
    lines += ["> " + z for z in (text or "").splitlines()[:200]] or ["> (empty)"]
    write_text(path, "\n".join(lines))
    return path


def rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(p)
