"""SQLite persistence for scans and results.

Design notes:
- WAL mode + one connection guarded by a lock: the scanner flushes batches
  from an asyncio task while HTTP handlers query concurrently. At our write
  rate (a few thousand rows/sec burst, batched) sqlite handles this fine.
- All dynamic SQL (sort columns) is validated against a whitelist — never
  interpolate user input into SQL.
"""

import json
import sqlite3
import threading
import time
from pathlib import Path

_LOCK = threading.Lock()
_CONN: sqlite3.Connection | None = None

# sort key -> column expression whitelist
SORTABLE = {
    "ts": "id",  # insertion order == time order
    "status": "status",
    "size": "content_length",
    "words": "word_count",
    "lines": "line_count",
    "url": "url",
    "score": "anomaly_score",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    wordlist TEXT NOT NULL,
    args_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'created',   -- created|running|finished|stopped|error
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    error TEXT,
    rows_total INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    url TEXT NOT NULL,
    path TEXT,
    method TEXT NOT NULL DEFAULT 'GET',
    status INTEGER NOT NULL,
    content_length INTEGER NOT NULL DEFAULT 0,
    line_count INTEGER NOT NULL DEFAULT 0,
    word_count INTEGER NOT NULL DEFAULT 0,
    redirect_url TEXT,
    anomaly_score REAL NOT NULL DEFAULT 0,
    anomaly_tags TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_results_status ON results(scan_id, status);
CREATE INDEX IF NOT EXISTS idx_results_size ON results(scan_id, content_length);
CREATE INDEX IF NOT EXISTS idx_results_score ON results(scan_id, anomaly_score);
"""


def init_db(db_path: str | Path) -> None:
    global _CONN
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _CONN = sqlite3.connect(str(db_path), check_same_thread=False)
    _CONN.row_factory = sqlite3.Row
    _CONN.execute("PRAGMA journal_mode=WAL")
    _CONN.execute("PRAGMA synchronous=NORMAL")
    _CONN.executescript(SCHEMA)
    _CONN.commit()


def _conn() -> sqlite3.Connection:
    if _CONN is None:
        raise RuntimeError("db not initialized")
    return _CONN


# ---------------------------------------------------------------- scans

def create_scan(target: str, wordlist: str, args: dict) -> int:
    with _LOCK:
        cur = _conn().execute(
            "INSERT INTO scans (target, wordlist, args_json, status, created_at) "
            "VALUES (?, ?, ?, 'created', ?)",
            (target, wordlist, json.dumps(args), time.time()),
        )
        _conn().commit()
        return int(cur.lastrowid or 0)


def set_scan_status(scan_id: int, status: str, error: str | None = None) -> None:
    now = time.time()
    with _LOCK:
        if status == "running":
            _conn().execute(
                "UPDATE scans SET status=?, started_at=? WHERE id=?",
                (status, now, scan_id),
            )
        elif status in ("finished", "stopped", "error"):
            _conn().execute(
                "UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                (status, now, error, scan_id),
            )
        else:
            _conn().execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
        _conn().commit()


def list_scans() -> list[dict]:
    with _LOCK:
        rows = _conn().execute(
            "SELECT id, target, wordlist, status, created_at, started_at, finished_at, "
            "rows_total, error FROM scans ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with _LOCK:
        row = _conn().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def delete_scan(scan_id: int) -> None:
    with _LOCK:
        _conn().execute("DELETE FROM results WHERE scan_id=?", (scan_id,))
        _conn().execute("DELETE FROM scans WHERE id=?", (scan_id,))
        _conn().commit()


# ---------------------------------------------------------------- results

def insert_results(scan_id: int, rows: list[dict]) -> None:
    """Batch insert. Each row: url,path,method,status,content_length,line_count,
    word_count,redirect_url,ts,anomaly_score,anomaly_tags."""
    if not rows:
        return
    payload = [
        (
            scan_id,
            r.get("ts", time.time()),
            r["url"],
            r.get("path", ""),
            r.get("method", "GET"),
            r["status"],
            r.get("content_length", 0),
            r.get("line_count", 0),
            r.get("word_count", 0),
            r.get("redirect_url"),
            r.get("anomaly_score", 0.0),
            r.get("anomaly_tags", ""),
        )
        for r in rows
    ]
    with _LOCK:
        _conn().executemany(
            "INSERT INTO results (scan_id, ts, url, path, method, status, content_length, "
            "line_count, word_count, redirect_url, anomaly_score, anomaly_tags) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            payload,
        )
        _conn().execute(
            "UPDATE scans SET rows_total = rows_total + ? WHERE id=?",
            (len(payload), scan_id),
        )
        _conn().commit()


def query_results(
    scan_id: int,
    status: list[int] | None = None,
    q: str | None = None,
    anomaly_only: bool = False,
    sort: str = "ts",
    direction: str = "asc",
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Return (rows, total_matching). sort must be a SORTABLE key."""
    col = SORTABLE.get(sort, "id")
    direction = "DESC" if direction.lower() == "desc" else "ASC"

    where = ["scan_id = ?"]
    params: list = [scan_id]

    if status:
        where.append("status IN (%s)" % ",".join("?" * len(status)))
        params.extend(status)
    if q:
        where.append("(url LIKE ? OR path LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like])
    if anomaly_only:
        where.append("anomaly_score > 0.5")

    where_sql = " AND ".join(where)

    with _LOCK:
        total = _conn().execute(
            f"SELECT COUNT(*) FROM results WHERE {where_sql}", params
        ).fetchone()[0]
        rows = _conn().execute(
            f"SELECT * FROM results WHERE {where_sql} ORDER BY {col} {direction}, id {direction} "
            "LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()

    return [dict(r) for r in rows], int(total)


def scan_stats(scan_id: int) -> dict:
    with _LOCK:
        con = _conn()
        by_status = con.execute(
            "SELECT status, COUNT(*) AS n, SUM(content_length) AS bytes "
            "FROM results WHERE scan_id=? GROUP BY status ORDER BY status",
            (scan_id,),
        ).fetchall()
        anom = con.execute(
            "SELECT COUNT(*) FROM results WHERE scan_id=? AND anomaly_score > 0.5",
            (scan_id,),
        ).fetchone()[0]
        size_hist = con.execute(
            "SELECT content_length, COUNT(*) AS n FROM results WHERE scan_id=? "
            "GROUP BY content_length ORDER BY n DESC LIMIT 12",
            (scan_id,),
        ).fetchall()
    return {
        "by_status": [dict(r) for r in by_status],
        "anomalies": int(anom),
        "top_sizes": [dict(r) for r in size_hist],
    }


def update_anomaly(scan_id: int, row_id: int, score: float, tags: str) -> None:
    with _LOCK:
        _conn().execute(
            "UPDATE results SET anomaly_score=?, anomaly_tags=? WHERE id=?",
            (score, tags, row_id),
        )


def commit() -> None:
    with _LOCK:
        _conn().commit()


def all_results(scan_id: int) -> list[dict]:
    with _LOCK:
        rows = _conn().execute(
            "SELECT id, status, content_length, line_count, word_count, anomaly_score "
            "FROM results WHERE scan_id=? ORDER BY id",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]
