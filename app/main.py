"""Ferox GUI — FastAPI app.

Routes:
  GET  /                      dashboard (static SPA)
  GET  /api/health
  GET  /api/stream            SSE: batch / status / stats events
  GET  /api/wordlists          bundled + uploaded lists
  POST /api/wordlists?name=    raw-body upload (binary-safe, no multipart limits)
  DEL  /api/wordlists/{name}
  GET  /api/scans             history
  POST /api/scans             start a scan
  GET  /api/scans/{id}        detail + stats
  POST /api/scans/{id}/stop
  POST /api/scans/{id}/reanalyze  exact MAD-based anomaly recompute
  DEL  /api/scans/{id}
  GET  /api/scans/{id}/results    filter/sort/paginate
"""

import asyncio
import json
import time
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .anomaly import recompute_scores
from .brief import build_brief
from .scanner import JOBS, ScanJob, broker, build_argv

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "wordlists"
BUILTIN_DIR = BASE_DIR / "wordlists"

app = FastAPI(title="Ferox GUI")
db.init_db(DATA_DIR / "ferox.db")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")

SAFE_NAME_SEP = ""


def _safe_name(name: str) -> str:
    cleaned = SAFE_NAME_SEP.join(c for c in name if c.isalnum() or c in "._-")
    if not cleaned or cleaned.startswith("."):
        raise HTTPException(400, "invalid wordlist name")
    return cleaned


def _wordlists() -> list[dict]:
    out = []
    for p in sorted(BUILTIN_DIR.glob("*.txt")):
        out.append({"name": p.name, "kind": "builtin", "words": _count_lines(p)})
    for p in sorted(UPLOAD_DIR.glob("*.txt")):
        out.append({"name": p.name, "kind": "uploaded", "words": _count_lines(p)})
    return out


def _count_lines(p: Path) -> int:
    try:
        with p.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _resolve_wordlist(name: str) -> Path:
    for directory in (UPLOAD_DIR, BUILTIN_DIR):
        p = directory / _safe_name(name)
        if p.is_file():
            return p
    raise HTTPException(404, f"wordlist not found: {name}")


# ------------------------------------------------------------------ pages

@app.get("/")
async def index() -> FileResponse:
    return FileResponse(BASE_DIR / "app" / "static" / "index.html")


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "now": time.time()}


# ------------------------------------------------------------------ wordlists

@app.get("/api/wordlists")
async def wordlists() -> list[dict]:
    return _wordlists()


@app.post("/api/wordlists")
async def upload_wordlist(request: Request, name: str = Query(...)) -> dict:
    safe = _safe_name(name if name.endswith(".txt") else f"{name}.txt")
    body = await request.body()
    if not body.strip():
        raise HTTPException(400, "empty wordlist")
    # basic sanity: one word per line, reject binaries
    if b"\x00" in body[:8192]:
        raise HTTPException(400, "does not look like a text wordlist")
    (UPLOAD_DIR / safe).write_bytes(body)
    return {"name": safe, "kind": "uploaded", "words": _count_lines(UPLOAD_DIR / safe)}


@app.delete("/api/wordlists/{name}")
async def delete_wordlist(name: str) -> dict:
    safe = _safe_name(name)
    target = UPLOAD_DIR / safe
    if not target.is_file():
        raise HTTPException(404, "only uploaded wordlists can be deleted")
    target.unlink()
    return {"deleted": safe}


# ------------------------------------------------------------------ scans

@app.get("/api/scans")
async def scans() -> list[dict]:
    return db.list_scans()


@app.post("/api/scans")
async def start_scan(payload: dict = Body(...)) -> dict:
    target = (payload.get("target") or "").strip()
    if not target.startswith(("http://", "https://")):
        raise HTTPException(400, "target must start with http:// or https://")

    wordlist_name = payload.get("wordlist") or "common.txt"
    wl_path = _resolve_wordlist(wordlist_name)

    extensions = [e.strip().lstrip(".") for e in payload.get("extensions", []) if e.strip()]
    methods = [m.upper() for m in payload.get("methods", []) if m.strip()]
    extra = payload.get("extra_args") or []
    if isinstance(extra, str):
        extra = extra.split()

    argv = build_argv(
        target=target,
        wordlist_path=str(wl_path),
        threads=int(payload.get("threads", 50)),
        depth=int(payload.get("depth", 4)),
        extensions=extensions,
        methods=methods,
        extra_args=extra,
        rate_limit=int(payload.get("rate_limit", 0) or 0),
        timeout=int(payload.get("timeout", 7)),
        insecure=bool(payload.get("insecure", False)),
        redirects=bool(payload.get("redirects", False)),
        add_slash=bool(payload.get("add_slash", False)),
        no_recursion=bool(payload.get("no_recursion", False)),
    )

    scan_id = db.create_scan(target, wordlist_name, {"argv": argv, **payload})
    job = ScanJob(scan_id, target, argv)
    JOBS[scan_id] = job
    await job.start()
    await broker.publish({"type": "status", "scan_id": scan_id, "status": "running"})
    return {"id": scan_id, "argv": argv}


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: int) -> dict:
    job = JOBS.get(scan_id)
    if not job:
        raise HTTPException(404, "scan not running")
    await job.stop()
    await broker.publish({"type": "status", "scan_id": scan_id, "status": job.status})
    return {"id": scan_id, "status": job.status}


@app.get("/api/scans/{scan_id}")
async def scan_detail(scan_id: int) -> dict:
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "no such scan")
    job = JOBS.get(scan_id)
    return {
        **scan,
        "args": json.loads(scan.get("args_json") or "{}"),
        "stats": db.scan_stats(scan_id),
        "live": bool(job and job.status == "running"),
    }


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int) -> dict:
    job = JOBS.get(scan_id)
    if job and job.status == "running":
        await job.stop()
    JOBS.pop(scan_id, None)
    db.delete_scan(scan_id)
    return {"deleted": scan_id}


@app.post("/api/scans/{scan_id}/reanalyze")
async def reanalyze(scan_id: int) -> dict:
    if not db.get_scan(scan_id):
        raise HTTPException(404, "no such scan")
    rows = db.all_results(scan_id)
    if not rows:
        return {"updated": 0}
    scored = recompute_scores(rows)
    for row, (score, tags) in zip(rows, scored):
        db.update_anomaly(scan_id, row["id"], score, tags)
    db.commit()
    await broker.publish({"type": "status", "scan_id": scan_id, "status": "reanalyzed"})
    return {"updated": len(rows)}


@app.get("/api/scans/{scan_id}/results")
async def results(
    scan_id: int,
    status: str | None = Query(None, description="comma separated status codes"),
    q: str | None = Query(None),
    anomaly: bool = Query(False),
    sort: str = Query("ts"),
    direction: str = Query("asc"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> dict:
    if not db.get_scan(scan_id):
        raise HTTPException(404, "no such scan")
    codes = [int(s) for s in status.split(",") if s.strip().isdigit()] if status else None
    rows, total = db.query_results(
        scan_id,
        status=codes,
        q=q,
        anomaly_only=anomaly,
        sort=sort,
        direction=direction,
        limit=limit,
        offset=offset,
    )
    return {"rows": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/api/scans/{scan_id}/brief")
async def scan_brief(scan_id: int) -> dict:
    """Compact triage digest — the agent-facing entry point (token economy)."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "no such scan")
    rows, _ = db.query_results(scan_id, sort="ts", direction="asc", limit=50000)
    return build_brief(scan, rows)


@app.get("/api/scans/{scan_id}/urls")
async def export_urls(
    scan_id: int,
    status: str | None = Query(None),
    q: str | None = Query(None),
    anomaly: bool = Query(False),
) -> dict:
    """Plain URL list honoring the same filters as /results — bulk copy/export."""
    if not db.get_scan(scan_id):
        raise HTTPException(404, "no such scan")
    codes = [int(s) for s in status.split(",") if s.strip().isdigit()] if status else None
    rows, total = db.query_results(
        scan_id, status=codes, q=q, anomaly_only=anomaly, sort="ts",
        direction="asc", limit=50000, offset=0,
    )
    return {"urls": [r["url"] for r in rows], "total": total}


# ------------------------------------------------------------------ SSE

@app.get("/api/stream")
async def stream(request: Request) -> StreamingResponse:
    queue = broker.subscribe()

    async def gen():
        # initial retry hint keeps EventSource happy on reconnect
        yield ": connected\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(msg)}\n\n"
        finally:
            broker.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.on_event("startup")
async def _startup() -> None:
    # clean up any stale job registry (fresh process)
    JOBS.clear()


@app.on_event("shutdown")
async def _shutdown() -> None:
    for job in list(JOBS.values()):
        await job.stop()
