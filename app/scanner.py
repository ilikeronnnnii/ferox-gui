"""Feroxbuster process management.

Runs `feroxbuster --silent --json` and parses stdout as NDJSON. Feroxbuster's
`--silent --json` mode prints one JSON object per finding and NO progress-bar
ANSI spam — this is the only sane way to pipe it into a UI.

Throughput protection:
- stdout lines are parsed in the reader coroutine and flushed to sqlite in
  batches (max 200 rows or 250ms), never one INSERT per line.
- SSE subscribers receive the same batches (not individual rows).
"""

import asyncio
import json
import os
import signal
import time
from pathlib import Path
from urllib.parse import urlparse

from . import db
from .anomaly import StreamingScorer

BATCH_MAX = 200
BATCH_INTERVAL = 0.25  # seconds


class ScanJob:
    def __init__(self, scan_id: int, target: str, argv: list[str]):
        self.scan_id = scan_id
        self.target = target
        self.argv = argv
        self.proc: asyncio.subprocess.Process | None = None
        self.status = "created"
        self.started_at: float | None = None
        self.stderr_tail: list[str] = []
        self._batch: list[dict] = []
        self._last_flush = 0.0
        self._scorer = StreamingScorer()
        self._dirty = False
        self._rows_seen = 0
        self._tasks: list[asyncio.Task] = []

    # ------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            *self.argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group -> clean kill of children
        )
        self.status = "running"
        self.started_at = time.time()
        db.set_scan_status(self.scan_id, "running")
        # keep strong refs: unreferenced create_task results can be GC'd mid-run
        self._tasks.append(asyncio.create_task(self._read_stderr()))
        self._tasks.append(asyncio.create_task(self._read_stdout()))
        self._tasks.append(asyncio.create_task(self._watch_exit()))

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            try:
                os.killpg(self.proc.pid, signal.SIGINT)  # ferox saves state on SIGINT
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if self.status == "running":
            self.status = "stopped"
            db.set_scan_status(self.scan_id, "stopped")

    # ------------------------------------------------------------- io loops

    async def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            if not text or not text.startswith("{"):
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                continue
            row = self._to_row(obj)
            if row is None:
                continue
            score, tags = self._scorer.score(row)
            row["anomaly_score"] = score
            row["anomaly_tags"] = ",".join(tags)
            self._batch.append(row)
            self._rows_seen += 1
            self._dirty = True
            if len(self._batch) >= BATCH_MAX or (
                time.time() - self._last_flush
            ) >= BATCH_INTERVAL:
                await self._flush()

    async def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                break
            self.stderr_tail.append(line.decode("utf-8", "replace").rstrip())
            if len(self.stderr_tail) > 50:
                self.stderr_tail = self.stderr_tail[-50:]

    async def _watch_exit(self) -> None:
        assert self.proc
        code = await self.proc.wait()
        # final drain
        await asyncio.sleep(BATCH_INTERVAL + 0.05)
        await self._flush()
        if self.status == "running":
            self.status = "finished" if code == 0 else "error"
            err = None if code == 0 else f"exit code {code}"
            db.set_scan_status(self.scan_id, self.status, err)

    async def _flush(self) -> None:
        if not self._batch:
            return
        batch, self._batch = self._batch, []
        self._last_flush = time.time()
        self._dirty = False
        try:
            db.insert_results(self.scan_id, batch)
        except Exception as exc:  # never let a db hiccup kill the read loop
            self.stderr_tail.append(f"[db] {exc}")
            return
        await broker.publish(
            {"type": "batch", "scan_id": self.scan_id, "rows": compact_rows(batch)}
        )

    # ------------------------------------------------------------- helpers

    def _to_row(self, obj: dict) -> dict | None:
        if obj.get("type") not in (None, "response"):
            return None
        url = obj.get("url")
        if not url:
            return None
        parsed = urlparse(url)
        return {
            "ts": time.time(),
            "url": url,
            "path": parsed.path or "/",
            "method": obj.get("method", "GET"),
            "status": int(obj.get("status", 0)),
            "content_length": int(obj.get("content_length", 0)),
            "line_count": int(obj.get("line_count", 0)),
            "word_count": int(obj.get("word_count", 0)),
            "redirect_url": (obj.get("headers") or {}).get("location"),
        }

    @property
    def rows_seen(self) -> int:
        return self._rows_seen


def compact_rows(rows: list[dict]) -> list[dict]:
    """Keep SSE payloads small: strip anything the UI table doesn't render."""
    keys = (
        "url",
        "path",
        "method",
        "status",
        "content_length",
        "line_count",
        "word_count",
        "redirect_url",
        "anomaly_score",
        "anomaly_tags",
    )
    return [{k: r.get(k) for k in keys} for r in rows]


# ---------------------------------------------------------------- broker

class Broker:
    """Tiny pub/sub for SSE fan-out. Bounded queues: a slow browser client
    gets its queue truncated (lossy), never blocks the scanner."""

    def __init__(self) -> None:
        self.subs: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subs.discard(q)

    async def publish(self, msg: dict) -> None:
        for q in list(self.subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # lossy: drop the oldest to keep the newest flowing
                try:
                    q.get_nowait()
                    q.put_nowait(msg)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass


broker = Broker()

# registry of running jobs: scan_id -> ScanJob
JOBS: dict[int, ScanJob] = {}


def build_argv(
    target: str,
    wordlist_path: str,
    threads: int = 50,
    depth: int = 4,
    extensions: list[str] | None = None,
    methods: list[str] | None = None,
    extra_args: list[str] | None = None,
    rate_limit: int = 0,
    timeout: int = 7,
    insecure: bool = False,
    redirects: bool = False,
    add_slash: bool = False,
    no_recursion: bool = False,
) -> list[str]:
    argv = [
        "feroxbuster",
        "-u",
        target,
        "--silent",
        "--json",
        "-w",
        wordlist_path,
        "-t",
        str(max(1, min(threads, 500))),
        "-d",
        str(max(0, depth)),
        "--timeout",
        str(max(1, timeout)),
    ]
    if extensions:
        for ext in extensions[:20]:
            argv += ["-x", ext]
    if methods:
        argv += ["-m", *methods[:5]]
    if rate_limit > 0:
        argv += ["--rate-limit", str(rate_limit)]
    if insecure:
        argv.append("-k")
    if redirects:
        argv.append("-r")
    if add_slash:
        argv.append("-f")
    if no_recursion:
        argv.append("-n")
    if extra_args:
        argv += extra_args
    return argv
