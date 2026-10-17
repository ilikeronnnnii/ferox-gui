"""Agent CLI for ferox-gui scan results.

Reads the sqlite DB directly — works with or without the web server running.
Designed for token economy: `brief` is the triage entry point; drill down with
`urls`/`export` only where needed.

Usage:
    python3 -m app.cli list
    python3 -m app.cli find <target-substring>
    python3 -m app.cli brief <scan_id> [--json]
    python3 -m app.cli urls  <scan_id> [--status 200,301] [--q admin] [--anomaly]
    python3 -m app.cli export <scan_id> [--out reports/<slug>/evidence]
"""

import argparse
import json
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import db  # noqa: E402
from app.brief import build_brief  # noqa: E402


def slugify_target(target: str) -> str:
    """http://example.com:8080 -> example_com_8080 (Cybermes convention)."""
    t = re.sub(r"^https?://", "", target.strip())
    t = t.split("/", 1)[0]
    t = re.sub(r"[^a-zA-Z0-9._-]", "_", t)
    return t.replace(".", "_")


def cmd_list(args) -> int:
    scans = db.list_scans()
    if not scans:
        print("no scans in db")
        return 0
    for s in scans:
        print(f"#{s['id']:<4} {s['status']:<10} rows={s['rows_total']:<7} {s['wordlist']:<14} {s['target']}")
    return 0


def cmd_find(args) -> int:
    hits = [s for s in db.list_scans() if args.substr.lower() in s["target"].lower()]
    for s in hits:
        print(f"#{s['id']} {s['status']} {s['target']} (rows={s['rows_total']})")
    if not hits:
        print(f"no scans matching '{args.substr}'")
    return 0


def _rows(scan_id: int, status: str | None, q: str | None, anomaly: bool):
    codes = [int(x) for x in status.split(",") if x.strip().isdigit()] if status else None
    rows, total = db.query_results(
        scan_id, status=codes, q=q, anomaly_only=anomaly,
        sort="ts", direction="asc", limit=50000,
    )
    return rows, total


def cmd_brief(args) -> int:
    scan = db.get_scan(args.scan_id)
    if not scan:
        print(f"no scan #{args.scan_id}", file=sys.stderr)
        return 1
    rows, _ = db.query_results(args.scan_id, sort="ts", direction="asc", limit=50000)
    brief = build_brief(scan, rows)
    if args.json:
        print(json.dumps(brief, indent=1))
        return 0

    s = brief["scan"]
    print(f"SCAN #{s['id']}  {s['status']}  rows={s['rows']}  wordlist={s['wordlist']}")
    print(f"target: {s['target']}")
    print("by status: " + "  ".join(f"{k}:{v}" for k, v in brief["by_status"].items()))
    for bucket, items in brief["highlights"].items():
        if not items:
            continue
        print(f"\n[{bucket}]")
        for it in items[:8]:
            print(f"  {it['status']}  {it['size']:>8}  {it['url']}  {it['why']}")
    if brief["largest"]:
        print("\n[largest files]")
        for it in brief["largest"]:
            print(f"  {it['size']:>8}  {it['url']}")
    print("\n[hints]")
    for h in brief["hints"]:
        print(f"  - {h}")
    return 0


def cmd_urls(args) -> int:
    rows, total = _rows(args.scan_id, args.status, args.q, args.anomaly)
    for r in rows:
        print(r["url"])
    print(f"# {total} urls", file=sys.stderr)
    return 0


def cmd_export(args) -> int:
    scan = db.get_scan(args.scan_id)
    if not scan:
        print(f"no scan #{args.scan_id}", file=sys.stderr)
        return 1
    rows, _ = db.query_results(args.scan_id, sort="ts", direction="asc", limit=50000)

    out = Path(args.out) if args.out else BASE_DIR.parent / "reports" / slugify_target(scan["target"]) / "evidence"
    out.mkdir(parents=True, exist_ok=True)
    sid = scan["id"]

    jsonl = out / f"ferox_{sid}.jsonl"
    jsonl.write_text("".join(json.dumps(r) + "\n" for r in rows))

    urls_txt = out / f"ferox_{sid}_urls.txt"
    urls_txt.write_text("".join(r["url"] + "\n" for r in rows))

    brief = build_brief(scan, rows)
    brief_json = out / f"ferox_{sid}_brief.json"
    brief_json.write_text(json.dumps(brief, indent=1))

    notes = out / "recon_notes.md"
    section = (
        f"\n## Feroxbuster scan #{sid} — {scan['target']}\n\n"
        f"- status: {scan['status']}, rows: {len(rows)}, wordlist: {scan['wordlist']}\n"
        f"- by status: {brief['by_status']}\n"
        f"- hints: " + "; ".join(brief["hints"]) + "\n"
        f"- artifacts: `{jsonl.name}`, `{urls_txt.name}`, `{brief_json.name}`\n"
    )
    existing = notes.read_text() if notes.exists() else "# Recon Notes\n"
    notes.write_text(existing + section)

    print(json.dumps({"jsonl": str(jsonl), "urls": str(urls_txt),
                      "brief": str(brief_json), "notes": str(notes)}, indent=1))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="ferox-gui-cli", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=str(BASE_DIR / "data" / "ferox.db"), help="path to ferox.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list all scans")
    f = sub.add_parser("find", help="find scans by target substring")
    f.add_argument("substr")
    b = sub.add_parser("brief", help="compact triage digest")
    b.add_argument("scan_id", type=int)
    b.add_argument("--json", action="store_true")
    u = sub.add_parser("urls", help="print result urls")
    u.add_argument("scan_id", type=int)
    u.add_argument("--status", help="comma separated codes, e.g. 200,301")
    u.add_argument("--q", help="substring filter on url")
    u.add_argument("--anomaly", action="store_true")
    e = sub.add_parser("export", help="write results into reports/<slug>/evidence/")
    e.add_argument("scan_id", type=int)
    e.add_argument("--out", help="override output dir")

    args = p.parse_args()
    db.init_db(args.db)
    return {"list": cmd_list, "find": cmd_find, "brief": cmd_brief,
            "urls": cmd_urls, "export": cmd_export}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
