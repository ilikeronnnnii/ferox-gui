"""Anomaly scoring for scan results.

Two-pass design:
1. Streaming pass (during scan): cheap rules + Welford running mean/std of
   log1p(size) per status group. O(1) per row, no cross-row storage.
2. Exact pass (on demand / scan end): median + MAD over the full result set,
   which is robust against the very outliers we're hunting.

The score is 0..1+ (1.0 = strong anomaly). Reasons are tagged so the UI can
explain *why* a row was flagged.
"""

import math
import statistics
from collections import defaultdict


class StreamingScorer:
    """Per-(scan,status) running stats + rarity counting."""

    def __init__(self, rarity_group_min: int = 25):
        self.stats: dict[int, dict] = defaultdict(
            lambda: {"n": 0, "mean": 0.0, "m2": 0.0, "sizes": defaultdict(int)}
        )
        self.rarity_group_min = rarity_group_min

    def _update(self, status: int, size: float) -> tuple[float, float, int]:
        s = self.stats[status]
        s["n"] += 1
        n = s["n"]
        delta = size - s["mean"]
        s["mean"] += delta / n
        s["m2"] += delta * (size - s["mean"])
        s["sizes"][int(size) if size >= 0 else 0] += 1
        var = s["m2"] / (n - 1) if n > 1 else 0.0
        return s["mean"], math.sqrt(var), n

    def score(self, row: dict) -> tuple[float, list[str]]:
        """Return (score, tags) for one result row."""
        tags: list[str] = []
        score = 0.0

        status = int(row.get("status", 0))
        size = max(int(row.get("content_length", 0)), 0)
        log_size = math.log1p(size)

        mean, std, n = self._update(status, log_size)

        # --- rule: empty / trivial body on a 2xx
        if 200 <= status < 300 and size <= 30:
            tags.append("empty-body-2xx")
            score = max(score, 0.9)

        # --- rule: 5xx is always worth a look
        if 500 <= status < 600:
            tags.append("server-error")
            score = max(score, 0.75)

        # --- rule: redirect off-target
        redirect = row.get("redirect_url") or ""
        base = (row.get("url") or "").split("/", 3)
        base_host = base[2] if len(base) > 2 else ""
        if redirect and "://" in redirect:
            redir_host = redirect.split("://", 1)[1].split("/", 1)[0]
            if redir_host and base_host and redir_host != base_host:
                tags.append("external-redirect")
                score = max(score, 0.8)

        # --- rule: rare content-length within a big status group
        if n >= self.rarity_group_min:
            count_same_size = self.stats[status]["sizes"][size]
            if count_same_size == 1:
                tags.append("rare-size")
                score = max(score, 0.6)

        # --- statistical: z-score of log1p(size), needs a baseline
        if n >= 15 and std > 1e-6:
            z = abs(log_size - mean) / std
            if z >= 2.75:
                tags.append("size-outlier")
                score = max(score, min(0.5 + z / 10.0, 1.0))

        return (round(score, 3), tags)


def recompute_scores(rows: list[dict]) -> list[tuple[float, str]]:
    """Exact second pass: per status group, robust z-score with median/MAD.
    Returns (score, tags) aligned with input rows. rows need id/status/
    content_length/line_count/word_count."""
    out: list[tuple[float, str]] = [(0.0, "") for _ in rows]
    groups: dict[int, list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        groups[int(r["status"])].append(i)

    for status, idxs in groups.items():
        sizes = [max(rows[i]["content_length"], 0) for i in idxs]
        if len(sizes) < 8:
            continue
        med = statistics.median(sizes)
        mad = statistics.median([abs(s - med) for s in sizes]) or 0.0

        for i in idxs:
            size = max(rows[i]["content_length"], 0)
            tags = [t for t in (out[i][1].split(",") if out[i][1] else []) if t]
            score = out[i][0]

            if mad > 0:
                rz = 0.6745 * (size - med) / mad
                if abs(rz) >= 3.5:
                    tags.append("mad-outlier")
                    score = max(score, min(0.55 + abs(rz) / 12.0, 1.0))
            elif size != med:
                # mad == 0: every peer is identical, so any deviation is maximal
                tags.append("mad-outlier")
                score = max(score, 0.75)

            # word/line ratio oddities: same status group, size normal, words extreme
            words = rows[i]["word_count"]
            if size > 200 and words == 0:
                tags.append("no-words")
                score = max(score, 0.65)

            out[i] = (round(score, 3), ",".join(dict.fromkeys(tags)))

    return out
