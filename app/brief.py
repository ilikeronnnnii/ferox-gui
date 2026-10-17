"""Agent-oriented scan digest.

The point of this module is token economy: an agent should be able to triage a
scan in ~one screen instead of paging through thousands of result rows. The
brief caps every list and classifies rows into highlight buckets that map to
"what a pentester looks at first".
"""

import re
from collections import Counter
from urllib.parse import urlparse

BACKUP_HINT = re.compile(
    r"(\.bak\d*$|\.old$|\.backup$|\.swp$|~$|\.tar$|\.tar\.gz$|\.tgz$|\.zip$|\.7z$|\.rar$|\.sql$|\.dump$|\.gz$)"
)
ADMIN_HINT = re.compile(
    r"(admin|login|signin|dashboard|wp-admin|wp-login|manage|console|panel|backend|cpanel|phpmyadmin|webmail)",
    re.I,
)
CONFIG_HINT = re.compile(
    r"(config|settings|\.env|web\.conf|appsettings|application\.(yml|yaml|properties|xml)|\.yml$|\.yaml$|\.toml$|\.ini$|\.conf$)",
    re.I,
)
DOTFILE_HINT = re.compile(r"/\.(git|env|htaccess|htpasswd|svn|DS_Store|well-known|idea|vscode|dockerignore)(/|$)|/\.[^/]+$")
CODE_EXT = {".php", ".asp", ".aspx", ".jsp", ".jspx", ".py", ".rb", ".js", ".ts", ".go", ".java", ".sh", ".cgi"}


def classify(row: dict) -> list[str]:
    """Return highlight tags for one result row."""
    tags: list[str] = []
    url = row.get("url", "")
    path = row.get("path", "") or urlparse(url).path
    status = int(row.get("status", 0))
    low = path.lower()

    if row.get("anomaly_score", 0) > 0.5:
        tags.append("anomalies")
    if BACKUP_HINT.search(low) and status < 400:
        tags.append("backups")
    if DOTFILE_HINT.search(low) and status < 400:
        tags.append("dotfiles")
    if ADMIN_HINT.search(low) and status < 400:
        tags.append("admin")
    if CONFIG_HINT.search(low) and status < 400:
        tags.append("config")
    if 500 <= status < 600:
        tags.append("server_errors")
    redir = row.get("redirect_url") or ""
    if redir.startswith("http"):
        host = urlparse(url).netloc
        if urlparse(redir).netloc and urlparse(redir).netloc != host:
            tags.append("external_redirects")
    if status < 400 and any(low.endswith(ext) or (ext + "?") in low for ext in CODE_EXT):
        tags.append("code_files")
    if (status in (200, 204) or (300 <= status < 400)) and (path.endswith("/") or row.get("content_length") == 0):
        tags.append("dirs")
    return tags


def _item(row: dict, why: list[str] | None = None) -> dict:
    why = why or []
    return {
        "url": row["url"],
        "status": row["status"],
        "size": row.get("content_length", 0),
        "why": ",".join(why) if why else str(row.get("anomaly_tags", "")),
    }


def build_brief(scan: dict, rows: list[dict], cap: int = 20) -> dict:
    """Compact triage digest for one scan. Every list is capped at `cap`."""
    buckets: dict[str, list] = {
        "anomalies": [], "backups": [], "dotfiles": [], "admin": [],
        "config": [], "server_errors": [], "external_redirects": [],
        "code_files": [], "dirs": [],
    }
    by_status: Counter = Counter()
    exts: Counter = Counter()
    seen_dirs: list[str] = []

    for row in rows:
        status = int(row.get("status", 0))
        by_status[status] += 1
        path = (row.get("path") or "").lower()
        if "." in path.rsplit("/", 1)[-1]:
            exts[path.rsplit(".", 1)[-1][:10]] += 1
        for tag in classify(row):
            if len(buckets[tag]) < cap:
                why = str(row.get("anomaly_tags") or tag) if tag == "anomalies" else tag
                buckets[tag].append(_item(row, [why]))
        if row.get("anomaly_score", 0) > 0.5 and not any(
            i["url"] == row["url"] for i in buckets["anomalies"]
        ):
            tags = [str(t) for t in str(row.get("anomaly_tags") or "anomaly").split(",")]
            buckets["anomalies"].insert(0, _item(row, tags))

    large = sorted(rows, key=lambda r: r.get("content_length", 0), reverse=True)[:5]
    for row in rows:
        p = row.get("path", "")
        if p.endswith("/") and len(seen_dirs) < cap:
            seen_dirs.append(p)

    hints = []
    if buckets["backups"]:
        hints.append(f"{len(buckets['backups'])}+ backup-like file(s) found — prioritize download/review")
    if buckets["dotfiles"]:
        hints.append("dotfiles present — check .git/.env/.htaccess exposure")
    if buckets["external_redirects"]:
        hints.append("external redirect(s) — possible open redirect / phishing surface")
    if by_status.get(401, 0) or by_status.get(403, 0):
        hints.append("auth-gated paths exist — candidates for 401/403 bypass or default-cred testing")
    if buckets["server_errors"]:
        hints.append("5xx responses present — fuzz those paths harder (params, methods)")
    if not hints:
        hints.append("no high-signal buckets populated; drill down with /api/scans/<id>/results?q=")

    return {
        "scan": {
            "id": scan.get("id"),
            "target": scan.get("target"),
            "status": scan.get("status"),
            "wordlist": scan.get("wordlist"),
            "rows": len(rows),
            "started_at": scan.get("started_at"),
            "finished_at": scan.get("finished_at"),
        },
        "by_status": dict(sorted(by_status.items())),
        "highlights": buckets,
        "largest": [_item(r, ["large-file"]) for r in large],
        "dirs_found": seen_dirs,
        "extensions": dict(exts.most_common(15)),
        "hints": hints,
    }
