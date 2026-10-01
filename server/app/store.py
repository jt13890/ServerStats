"""Latest-sample cache plus SQLite history of host-level metrics.

History is kept forever, in tiers so years of it stay small:

  history      every sample (~15s)       kept RAW_DAYS, then only as averages
  history_5m   5-minute averages         kept M5_DAYS, then only as averages
  history_1h   1-hour averages           kept until pruned from the dashboard

A background job rolls samples up into the coarser tiers; queries pick the
coarsest tier that still has enough detail for the requested range and fill
in the not-yet-rolled-up recent part from the finer tiers. Nothing is
deleted outright unless someone prunes it (Store.prune_older_than) or
removes the host.
"""

import json
import math
import sqlite3
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path

# Filesystem usage changes slowly; record it at most this often per host.
STORAGE_SAMPLE_SECONDS = 300
RAW_DAYS = 3
M5_DAYS = 90
DAY = 86400

# Host-level metrics tracked over time (all nullable REAL columns).
METRICS = (
    "cpu", "mem", "swap", "load1", "load5", "load15", "rx", "tx",
    "disk_util", "disk_read", "disk_write", "storage", "procs", "threads",
)
# Percentages are clamped when averaged, so bad values that older agents
# stored can't blow up the charts.
PERCENT_METRICS = {"cpu", "mem", "swap", "disk_util", "storage"}
# Components of a host's overall load score (see load_of).
# Storage isn't part of it: a full disk has its own meter, and it's not load.
LOAD_PARTS = ("cpu", "mem", "disk_util")
LOAD_HOURS = RAW_DAYS * 24  # the "Load · 3d" average
PEAK_DAYS = 7               # the "1% high" and the load peaks section
SLOT = 300                  # load is scored per 5-minute slot
# What was running at the busiest moment of each slot, for explaining peaks.
# After SNAPSHOT_DAYS only the busiest one of each hour is kept.
SNAPSHOT_DAYS = 30
SNAPSHOT_PROCS = 6          # top processes by CPU, and again by memory
SNAPSHOT_STACKS = 6
SNAPSHOT_DISKS = 3


def _avg(m: str) -> str:
    return f"AVG(MIN(MAX({m}, 0), 100))" if m in PERCENT_METRICS else f"AVG({m})"


# Tiers from finest to coarsest: (table, resolution seconds, rollup marker).
# Every table holding a host's history (column `host`, timestamp `ts`).
HOST_TABLES = ("history", "history_5m", "history_1h", "storage_history", "storage_1h", "load_snapshots")

TIERS = (("history", 0, None), ("history_5m", 300, "m5"), ("history_1h", 3600, "h1"))
STORAGE_TIERS = (("storage_history", STORAGE_SAMPLE_SECONDS, None), ("storage_1h", 3600, "s1h"))


@dataclass
class HostState:
    data: dict | None = None
    received_at: float | None = None
    error: str | None = None
    error_at: float | None = None
    host_key: str | None = None  # SSH host key fingerprint seen on last connect


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def metrics_from_sample(data: dict) -> dict:
    """Pick the host-level numbers we keep history for out of a sample."""
    cpu, mem, net, dio, tasks = (data.get(k) or {} for k in ("cpu", "memory", "net", "disk_io", "tasks"))
    load = (data.get("load") or []) + [None] * 3
    swap_total = _num(mem.get("swap_total")) or 0
    disks = [d.get("percent") for d in data.get("disks") or [] if isinstance(d, dict)]
    return {
        "cpu": _num(cpu.get("percent")),
        "mem": _num(mem.get("percent")),
        # No swap configured -> no swap series, rather than a flat 0% line.
        "swap": 100.0 * (_num(mem.get("swap_used")) or 0) / swap_total if swap_total else None,
        "load1": _num(load[0]), "load5": _num(load[1]), "load15": _num(load[2]),
        "rx": _num(net.get("rx_rate")), "tx": _num(net.get("tx_rate")),
        "disk_util": _num(dio.get("util")),
        "disk_read": _num(dio.get("read_rate")), "disk_write": _num(dio.get("write_rate")),
        "storage": max((p for p in disks if _num(p) is not None), default=None),
        "procs": _num(tasks.get("total")), "threads": _num(tasks.get("threads")),
    }


def load_of(u: dict) -> tuple[float, dict]:
    """Overall load (0-100) from component percentages, and each one's share.

    Sandpiper's "volume" (Wood et al., NSDI 2007) combines resources as
    V = 1/((1-cpu)(1-mem)(1-disk)): it grows the more heavily any resource
    is used, and faster still when several are. As a percentage that's
    load = 100 * (1 - 1/V) = 100 * (1 - (1-cpu)(1-mem)(1-disk)), which
    reads 100% exactly when something is maxed out.

    Each resource's share is its factor in V, -ln(1-u), as a fraction of
    ln V. Like queueing delay it grows sharply the closer a resource is to
    full, yet a quieter one still gets a visible share. The shares add up
    to the load.
    """
    vals = {k: min(max(v, 0.0), 100.0) for k, v in u.items() if k in LOAD_PARTS and _num(v) is not None}
    if not vals:
        return 0.0, {}
    free = math.prod(1 - v / 100 for v in vals.values())
    load = 100 * (1 - free)
    # 99.9% stands in for 100% so a maxed-out resource has a finite weight.
    weight = {k: 0.0 - math.log(1 - min(v, 99.9) / 100) for k, v in vals.items()}  # (0.0 - avoids -0.0)
    total = sum(weight.values())
    return load, {k: (load * w / total if total > 0 else 0.0) for k, w in weight.items()}


def _group_stacks(containers: list) -> list:
    """Docker containers summed per compose project (standalone ones alone)."""
    stacks: dict[str, dict] = {}
    for c in containers:
        if not isinstance(c, dict):
            continue
        name = c.get("project") or c.get("name") or "?"
        st = stacks.setdefault(name, {"name": name, "stack": bool(c.get("project")), "containers": 0,
                                      "cpu": 0.0, "mem": 0.0, "mem_percent": 0.0, "read_rate": 0.0, "write_rate": 0.0})
        st["containers"] += 1
        for k in ("cpu", "mem", "mem_percent", "read_rate", "write_rate"):
            st[k] += _num(c.get(k)) or 0.0
    return list(stacks.values())


def peak_snapshot(data: dict, values: dict, load: float, parts: dict) -> dict:
    """The few things worth keeping about one moment, to explain a load peak."""
    procs = [p for p in data.get("processes") or [] if isinstance(p, dict)]
    keep: dict[int, dict] = {}
    for key in ("cpu", "mem"):
        for p in sorted(procs, key=lambda p: _num(p.get(key)) or 0, reverse=True)[:SNAPSHOT_PROCS]:
            keep[p.get("pid")] = {k: p.get(k) for k in ("pid", "name", "user", "cpu", "mem", "rss")} | {
                "cmd": str(p.get("cmd") or "")[:160]}
    dk = data.get("docker") or {}
    stacks = sorted(_group_stacks(dk.get("containers") or []), key=lambda s: s["cpu"] + s["mem_percent"], reverse=True)
    dio = data.get("disk_io") or {}
    disks = sorted((d for d in dio.get("devices") or [] if isinstance(d, dict)),
                   key=lambda d: _num(d.get("util")) or 0, reverse=True)[:SNAPSHOT_DISKS]
    return {
        "load": round(load, 1),
        "parts": {k: round(v, 1) for k, v in parts.items()},
        "values": {k: (round(v, 1) if v is not None else None) for k, v in values.items()},
        "ncpu": (data.get("cpu") or {}).get("count"),
        "mem_total": (data.get("memory") or {}).get("total"),
        "processes": list(keep.values()),
        "stacks": [{k: (round(v, 2) if isinstance(v, float) else v) for k, v in st.items()}
                   for st in stacks[:SNAPSHOT_STACKS]] if dk.get("containers") else None,
        "disks": [{k: d.get(k) for k in ("label", "util", "read_rate", "write_rate")} for d in disks],
    }


class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        cols = ", ".join(f"{m} REAL" for m in METRICS)
        self._db.executescript(
            f"""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS history (host TEXT NOT NULL, ts REAL NOT NULL, {cols});
            CREATE INDEX IF NOT EXISTS history_host_ts ON history(host, ts);
            CREATE INDEX IF NOT EXISTS history_ts ON history(ts);
            CREATE TABLE IF NOT EXISTS history_5m (host TEXT NOT NULL, ts REAL NOT NULL, {cols},
                                                   PRIMARY KEY (host, ts));
            CREATE TABLE IF NOT EXISTS history_1h (host TEXT NOT NULL, ts REAL NOT NULL, {cols},
                                                   PRIMARY KEY (host, ts));
            CREATE TABLE IF NOT EXISTS storage_history (
                host TEXT NOT NULL, ts REAL NOT NULL, mount TEXT NOT NULL,
                used REAL NOT NULL, total REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS storage_host_ts ON storage_history(host, ts);
            CREATE INDEX IF NOT EXISTS storage_ts ON storage_history(ts);
            CREATE TABLE IF NOT EXISTS storage_1h (
                host TEXT NOT NULL, ts REAL NOT NULL, mount TEXT NOT NULL,
                used REAL NOT NULL, total REAL NOT NULL,
                PRIMARY KEY (host, ts, mount)
            );
            CREATE TABLE IF NOT EXISTS latest (
                host TEXT PRIMARY KEY, received_at REAL NOT NULL, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS host_prefs (name TEXT PRIMARY KEY, docker INTEGER);
            CREATE TABLE IF NOT EXISTS load_snapshots (
                host TEXT NOT NULL, slot INTEGER NOT NULL, ts REAL NOT NULL,
                load REAL NOT NULL, data BLOB NOT NULL,
                PRIMARY KEY (host, slot)
            );
            CREATE TABLE IF NOT EXISTS enrolled (
                name TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                hostname TEXT, created REAL NOT NULL
            );
            """
        )
        # Databases from earlier versions lack some metric columns.
        existing = {row[1] for row in self._db.execute("PRAGMA table_info(history)")}
        for m in METRICS:
            if m not in existing:
                self._db.execute(f"ALTER TABLE history ADD COLUMN {m} REAL")
        self._db.commit()

        self.states: dict[str, HostState] = {}
        self._storage_last: dict[str, float] = {}
        self._snapshot_best: dict[str, tuple[int, float]] = {}  # host -> (slot, load) already stored
        for host, received_at, data in self._db.execute("SELECT host, received_at, data FROM latest"):
            self.states[host] = HostState(data=json.loads(data), received_at=received_at)

    def state(self, host: str) -> HostState:
        return self.states.setdefault(host, HostState())

    # -- writes -------------------------------------------------------------

    def record(self, host: str, data: dict, now: float | None = None) -> None:
        now = time.time() if now is None else now
        st = self.state(host)
        st.data, st.received_at, st.error, st.error_at = data, now, None, None
        m = metrics_from_sample(data)
        with self._lock, self._db:
            self._db.execute(
                f"INSERT INTO history (host, ts, {', '.join(METRICS)}) VALUES (?, ?, {', '.join('?' * len(METRICS))})",
                (host, now, *(m[k] for k in METRICS)),
            )
            if now - self._storage_last.get(host, 0) >= STORAGE_SAMPLE_SECONDS:
                self._storage_last[host] = now
                self._db.executemany(
                    "INSERT INTO storage_history (host, ts, mount, used, total) VALUES (?,?,?,?,?)",
                    [
                        (host, now, str(d.get("mount")), float(d.get("used") or 0), float(d.get("total") or 0))
                        for d in (data.get("disks") or [])[:32]
                        if isinstance(d, dict) and d.get("total")
                    ],
                )
            self._record_snapshot(host, data, m, now)
            self._db.execute(
                "INSERT OR REPLACE INTO latest (host, received_at, data) VALUES (?,?,?)",
                (host, now, json.dumps(data, separators=(",", ":"))),
            )

    def _record_snapshot(self, host: str, data: dict, m: dict, now: float) -> None:
        """Keep the busiest moment of each 5-minute slot (caller holds the lock)."""
        values = {k: m.get(k) for k in LOAD_PARTS}
        load, parts = load_of(values)
        slot = int(now // SLOT)
        best = self._snapshot_best.get(host)
        if best is not None and best[0] == slot and best[1] >= load:
            return
        if best is None or best[0] != slot:
            row = self._db.execute("SELECT load FROM load_snapshots WHERE host = ? AND slot = ?", (host, slot)).fetchone()
            if row is not None and row[0] >= load:
                self._snapshot_best[host] = (slot, row[0])
                return
        self._snapshot_best[host] = (slot, load)
        blob = zlib.compress(json.dumps(peak_snapshot(data, values, load, parts), separators=(",", ":")).encode())
        self._db.execute("INSERT OR REPLACE INTO load_snapshots (host, slot, ts, load, data) VALUES (?,?,?,?,?)",
                         (host, slot, now, load, blob))

    def record_error(self, host: str, error: str) -> None:
        st = self.state(host)
        st.error, st.error_at = error, time.time()

    # -- hosts that joined with the join key ---------------------------------

    def enrolled_hosts(self) -> list[tuple[str, str]]:
        with self._lock:
            return self._db.execute("SELECT name, token_hash FROM enrolled ORDER BY created").fetchall()

    def enroll(self, name: str, token_hash: str, hostname: str) -> bool:
        """Register a host; False if the name is already taken."""
        with self._lock, self._db:
            try:
                self._db.execute(
                    "INSERT INTO enrolled (name, token_hash, hostname, created) VALUES (?,?,?,?)",
                    (name, token_hash, hostname, time.time()),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def docker_pref(self, name: str) -> bool | None:
        """Docker on/off chosen in the dashboard; None = the agent's install-time default."""
        with self._lock:
            row = self._db.execute("SELECT docker FROM host_prefs WHERE name = ?", (name,)).fetchone()
        return None if row is None or row[0] is None else bool(row[0])

    def set_docker_pref(self, name: str, enabled: bool) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO host_prefs (name, docker) VALUES (?, ?)", (name, int(enabled)))

    def remove_host(self, name: str) -> None:
        """Forget an enrolled host and all of its data."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM host_prefs WHERE name = ?", (name,))
            for table in ("enrolled", "latest", *HOST_TABLES):
                self._db.execute(f"DELETE FROM {table} WHERE {'name' if table == 'enrolled' else 'host'} = ?", (name,))
        self.states.pop(name, None)

    # -- rollups, compaction and pruning ------------------------------------

    def _mark(self, key: str) -> float:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else 0.0

    def _set_mark(self, key: str, value: float) -> None:
        self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def rollup(self, now: float | None = None) -> None:
        """Average finished periods into the coarser tiers. Safe to re-run."""
        now = time.time() if now is None else now
        avgs = ", ".join(_avg(m) for m in METRICS)
        with self._lock, self._db:
            until = now
            for (src, _, _), (dst, res, key) in zip(TIERS, TIERS[1:]):
                start, end = self._mark(key), (until // res) * res
                if end > start:
                    self._db.execute(
                        f"""INSERT OR REPLACE INTO {dst} (host, ts, {', '.join(METRICS)})
                            SELECT host, CAST(ts / {res} AS INTEGER) * {res}, {avgs}
                            FROM {src} WHERE ts >= ? AND ts < ? GROUP BY 1, 2""",
                        (start, end),
                    )
                    self._set_mark(key, end)
                # The next tier can only include what this one has finished.
                until = self._mark(key)

            (src, _, _), (dst, res, key) = STORAGE_TIERS
            start, end = self._mark(key), (now // res) * res
            if end > start:
                self._db.execute(
                    f"""INSERT OR REPLACE INTO {dst} (host, ts, mount, used, total)
                        SELECT host, CAST(ts / {res} AS INTEGER) * {res}, mount, AVG(used), AVG(total)
                        FROM {src} WHERE ts >= ? AND ts < ? GROUP BY 1, 2, 3""",
                    (start, end),
                )
                self._set_mark(key, end)

    def compact(self, known_hosts: set[str], now: float | None = None) -> None:
        """Drop fine-grained rows that the coarser tiers now cover, and data
        for hosts removed from the config. Hourly history is kept forever."""
        now = time.time() if now is None else now
        with self._lock, self._db:
            # Never drop fine-grained rows that haven't been rolled up yet.
            cutoffs = {
                "history": min(now - RAW_DAYS * DAY, self._mark("m5")),
                "history_5m": min(now - M5_DAYS * DAY, self._mark("h1")),
                "storage_history": min(now - M5_DAYS * DAY, self._mark("s1h")),
            }
            for table, cutoff in cutoffs.items():
                self._db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
            # Peak snapshots: past SNAPSHOT_DAYS, keep only each hour's busiest.
            per_hour = 3600 // SLOT
            start = self._mark("snap1h")
            end = ((now - SNAPSHOT_DAYS * DAY) // 3600) * 3600
            if end > start:
                self._db.execute(
                    f"""DELETE FROM load_snapshots AS a WHERE ts >= ? AND ts < ? AND EXISTS (
                            SELECT 1 FROM load_snapshots AS b
                            WHERE b.host = a.host AND b.slot / {per_hour} = a.slot / {per_hour} AND b.slot != a.slot
                              AND (b.load > a.load OR (b.load = a.load AND b.slot < a.slot)))""",
                    (start, end),
                )
                self._set_mark("snap1h", end)
            # Drop data for hosts that were removed from the config.
            for (host,) in self._db.execute("SELECT DISTINCT host FROM latest").fetchall():
                if host not in known_hosts:
                    for table in ("latest", *HOST_TABLES):
                        self._db.execute(f"DELETE FROM {table} WHERE host = ?", (host,))
                    self.states.pop(host, None)

    def prune_preview(self, days: float, host: str | None = None) -> dict:
        """What prune_older_than(days, host) would delete."""
        cutoff = time.time() - days * DAY
        where = "ts < ?" + (" AND host = ?" if host else "")
        params = (cutoff, host) if host else (cutoff,)
        rows, oldest, hosts = 0, None, set()
        with self._lock:
            for table in HOST_TABLES:
                n, lo = self._db.execute(f"SELECT COUNT(*), MIN(ts) FROM {table} WHERE {where}", params).fetchone()
                rows += n
                if lo is not None and (oldest is None or lo < oldest):
                    oldest = lo
                hosts.update(h for (h,) in self._db.execute(f"SELECT DISTINCT host FROM {table} WHERE {where}", params))
        return {"cutoff": cutoff, "rows": rows, "oldest": oldest, "hosts": sorted(hosts)}

    def prune_older_than(self, days: float, host: str | None = None) -> dict:
        """Delete all history older than `days` (for one host, or all), then
        give the space back to the filesystem."""
        cutoff = time.time() - days * DAY
        where = "ts < ?" + (" AND host = ?" if host else "")
        params = (cutoff, host) if host else (cutoff,)
        with self._lock:
            before = self._db_bytes()
            with self._db:
                rows = sum(self._db.execute(f"DELETE FROM {table} WHERE {where}", params).rowcount
                           for table in HOST_TABLES)
            if rows:
                self._db.execute("VACUUM")
            after = self._db_bytes()
        return {"cutoff": cutoff, "rows": rows, "freed": max(before - after, 0)}

    def _db_bytes(self) -> int:
        pages = self._db.execute("PRAGMA page_count").fetchone()[0]
        return pages * self._db.execute("PRAGMA page_size").fetchone()[0]

    # -- reads --------------------------------------------------------------

    def _union(self, tiers, bucket: float, host: str, since: float, columns: str):
        """SQL + params selecting `columns` for one host from the coarsest tier
        whose resolution fits `bucket`, plus finer tiers for the recent part
        that hasn't been rolled up yet, plus coarser tiers for anything older
        than that tier still keeps (e.g. zooming into a day long ago: raw
        samples are gone, the 5-minute or hourly averages are what's left)."""
        usable = [t for t in tiers if t[1] <= bucket] or [tiers[0]]
        parts, params, lo = [], [], since
        for table, _, key in reversed(usable):  # coarsest first
            hi = self._mark(key) if key else None
            if hi is not None and hi <= lo:
                continue
            cond = "ts >= ?" + (" AND ts < ?" if hi is not None else "")
            parts.append(f"SELECT ts, {columns} FROM {table} WHERE host = ? AND {cond}")
            params += [host, lo] + ([hi] if hi is not None else [])
            if hi is not None:
                lo = hi
        # Older than the chosen tier keeps: fill in from the coarser ones.
        oldest = lambda table: self._db.execute(f"SELECT MIN(ts) FROM {table} WHERE host = ?", (host,)).fetchone()[0]
        upper = oldest(usable[-1][0])
        for table, _, _ in tiers[len(usable):]:
            if upper is not None and upper <= since:
                break
            parts.append(f"SELECT ts, {columns} FROM {table} WHERE host = ? AND ts >= ?"
                         + (" AND ts < ?" if upper is not None else ""))
            params += [host, since] + ([upper] if upper is not None else [])
            here = oldest(table)
            if here is not None:
                upper = here if upper is None else min(upper, here)
        return " UNION ALL ".join(parts), params

    def history(self, host: str, hours: float, points: int = 240,
                start: float | None = None, end: float | None = None) -> dict:
        """About `points` averaged points over the last `hours`, or over
        [start, end) when given (a zoomed-in chart)."""
        if start is not None and end is not None:
            since, until = start, end
        else:
            hours = min(max(hours, 0.1), 100 * 365 * 24)
            until = time.time() + 1
            since = until - 1 - hours * 3600
        bucket = max((until - since) / points, 1)
        sbucket = max(bucket, STORAGE_SAMPLE_SECONDS)
        with self._lock:
            union, params = self._union(TIERS, bucket, host, since, ", ".join(METRICS))
            rows = self._db.execute(
                f"""SELECT CAST(ts / ? AS INTEGER) * ? AS t, {', '.join(_avg(m) for m in METRICS)}
                    FROM ({union}) WHERE ts < ? GROUP BY 1 ORDER BY 1""",
                (bucket, bucket, *params, until),
            ).fetchall()
            union, params = self._union(STORAGE_TIERS, sbucket, host, since - sbucket, "mount, used, total")
            srows = self._db.execute(
                f"""SELECT CAST(ts / ? AS INTEGER) * ? AS t, mount, AVG(used), AVG(total)
                    FROM ({union}) WHERE ts < ? GROUP BY 1, 2 ORDER BY 1""",
                (sbucket, sbucket, *params, until),
            ).fetchall()
        keys = ("t", *METRICS)
        metrics = [{k: (round(v, 2) if isinstance(v, float) else v) for k, v in zip(keys, row)} for row in rows]
        storage: dict[str, list] = {}
        for t, mount, used, total in srows:
            storage.setdefault(mount, []).append({"t": t, "used": used, "total": total})
        return {"bucket": bucket, "metrics": metrics, "storage": storage}

    def _load_slots(self, since: float, host: str | None = None) -> dict[str, list]:
        """Per-host, per-5-minute-slot load since `since`: {host: [(t, load, parts, values)]}.

        Rolled-up 5-minute averages cover what's older than the last rollup;
        raw samples, averaged per slot the same way, cover the rest.
        """
        cols = ", ".join(_avg(k) for k in LOAD_PARTS)
        where = " AND host = ?" if host else ""
        with self._lock:
            mark = max(self._mark("m5"), since)
            rows = self._db.execute(
                f"""SELECT host, CAST(ts / {SLOT} AS INTEGER) AS s, {', '.join(LOAD_PARTS)}
                        FROM history_5m WHERE ts >= ? AND ts < ?{where}
                    UNION ALL
                    SELECT host, CAST(ts / {SLOT} AS INTEGER) AS s, {cols}
                        FROM history WHERE ts >= ?{where} GROUP BY 1, 2
                    ORDER BY 1, 2""",
                (since, mark, *([host] if host else []), mark, *([host] if host else [])),
            ).fetchall()
        out: dict[str, list] = {}
        for h, slot, *vals in rows:
            u = dict(zip(LOAD_PARTS, vals))
            if all(v is None for v in u.values()):
                continue
            load, parts = load_of(u)
            out.setdefault(h, []).append((slot * SLOT, load, parts, u))
        return out

    @staticmethod
    def _one_percent_high(slots: list) -> dict:
        """The busiest 1% of slots (at least one), averaged."""
        k = max(1, math.ceil(len(slots) * 0.01))
        top = sorted(slots, key=lambda s: s[1], reverse=True)[:k]
        return {
            "load": round(sum(s[1] for s in top) / k, 1),
            "parts": {p: round(sum(s[2].get(p, 0.0) for s in top) / k, 1) for p in LOAD_PARTS},
            "slots": k,
            "hours": round(len(slots) * SLOT / 3600, 1),
        }

    def load_scores(self, hours: float = LOAD_HOURS, peak_days: float = PEAK_DAYS) -> dict:
        """Each host's overall load: the average over `hours` (all slots with
        data, each scored with load_of), and the 1% high over `peak_days`."""
        now = time.time()
        since = now - hours * 3600
        hosts = {}
        for host, slots in self._load_slots(now - max(hours * 3600, peak_days * DAY)).items():
            recent = [s for s in slots if s[0] >= since - SLOT]
            score = {"high1": self._one_percent_high([s for s in slots if s[0] >= now - peak_days * DAY - SLOT])}
            if recent:
                n = len(recent)
                avg = {}
                for k in LOAD_PARTS:
                    seen = [s[3][k] for s in recent if s[3].get(k) is not None]
                    avg[k] = round(sum(seen) / len(seen), 1) if seen else None
                score.update({
                    "load": round(sum(s[1] for s in recent) / n, 1),
                    "parts": {k: round(sum(s[2].get(k, 0.0) for s in recent) / n, 1) for k in LOAD_PARTS},
                    "avg": avg,
                    "hours": round(n * SLOT / 3600, 1),
                })
            hosts[host] = score
        return {"window_hours": hours, "peak_days": peak_days, "hosts": hosts}

    def load_week(self, host: str, days: float = PEAK_DAYS, peaks: int = 5) -> dict:
        """One host's load per 5-minute slot, its 1% high, and its busiest
        separate times (at least 3 hours apart), for the load peaks section."""
        slots = self._load_slots(time.time() - days * DAY, host).get(host, [])
        chosen: list = []
        for s in sorted(slots, key=lambda s: s[1], reverse=True):
            if len(chosen) >= peaks or s[1] <= 0:
                break
            if all(abs(s[0] - c[0]) >= 3 * 3600 for c in chosen):
                chosen.append(s)
        r1 = lambda v: round(v, 1) if v is not None else None
        return {
            "days": days,
            "slot": SLOT,
            # Columns rather than rows: a week is ~2000 slots.
            "t": [s[0] for s in slots],
            "load": [r1(s[1]) for s in slots],
            "parts": {k: [r1(s[2].get(k, 0.0)) for s in slots] for k in LOAD_PARTS},
            "values": {k: [r1(s[3].get(k)) for s in slots] for k in LOAD_PARTS},
            "high1": self._one_percent_high(slots) if slots else None,
            "peaks": [{"t": s[0], "load": r1(s[1])} for s in chosen],
        }

    def load_moment(self, host: str, t: float, span: float = SLOT) -> dict | None:
        """What was running at the busiest recorded moment within [t, t+span)
        (for spans under 5 minutes: within the 5 minutes at t)."""
        first = int(t // SLOT)
        last = max(first, math.ceil((t + span) / SLOT) - 1)
        with self._lock:
            row = self._db.execute(
                """SELECT ts, data FROM load_snapshots WHERE host = ? AND slot >= ? AND slot <= ?
                   ORDER BY load DESC LIMIT 1""", (host, first, last),
            ).fetchone()
        if row is None:
            return None
        snap = json.loads(zlib.decompress(row[1]))
        # Re-score from the stored values, so moments saved under an older
        # load formula read the same as everything else.
        load, parts = load_of(snap.get("values") or {})
        snap.update(load=round(load, 1), parts={k: round(v, 1) for k, v in parts.items()})
        return {"ts": row[0], **snap}

    def moment(self, host: str, t: float, span: float) -> dict:
        """Everything known about [t, t+span): average stats (from the same
        tiers the charts use), storage per mount, the load they add up to,
        and what was running at the busiest recorded moment."""
        span = min(max(span, 1.0), 400 * DAY)
        r = lambda v: round(v, 2) if isinstance(v, float) else v
        with self._lock:
            union, params = self._union(TIERS, span, host, t, ", ".join(METRICS))
            row = self._db.execute(
                f"SELECT COUNT(*), {', '.join(_avg(m) for m in METRICS)} FROM ({union}) WHERE ts < ?",
                (*params, t + span),
            ).fetchone()
            if not row[0]:
                # Only coarser averages are left for this time (e.g. 5-minute
                # rows for a 1-minute point): use the one that covers t.
                union, params = self._union(TIERS, span, host, t - 3600, ", ".join(METRICS))
                row = self._db.execute(
                    f"""SELECT COUNT(*), {', '.join(_avg(m) for m in METRICS)} FROM (
                            SELECT * FROM ({union}) WHERE ts <= ? ORDER BY ts DESC LIMIT 1)""",
                    (*params, t),
                ).fetchone()
            sspan = max(span, STORAGE_SAMPLE_SECONDS)
            union, params = self._union(STORAGE_TIERS, sspan, host, t - STORAGE_SAMPLE_SECONDS, "mount, used, total")
            mounts = self._db.execute(
                f"SELECT mount, AVG(used), AVG(total) FROM ({union}) WHERE ts < ? GROUP BY mount ORDER BY mount",
                (*params, t + sspan),
            ).fetchall()
        stats = dict(zip(METRICS, map(r, row[1:]))) if row[0] else None
        load = None
        if stats:
            value, parts = load_of({k: stats.get(k) for k in LOAD_PARTS})
            load = {"load": round(value, 1), "parts": {k: round(v, 1) for k, v in parts.items()},
                    "values": {k: stats.get(k) for k in LOAD_PARTS}}
        return {
            "t": t, "span": span, "stats": stats, "load": load,
            "storage": [{"mount": m, "used": u, "total": tot} for m, u, tot in mounts],
            "snapshot": self.load_moment(host, t, span),
        }

    def trends(self, hours: float = 1.0, points: int = 60) -> dict:
        """Recent CPU/memory/disk/storage for every host (overview sparklines)."""
        bucket = max(hours * 3600 / points, 1)
        since = time.time() - hours * 3600
        keys = ("cpu", "mem", "disk_util", "storage")
        with self._lock:
            rows = self._db.execute(
                f"""SELECT host, CAST(ts / ? AS INTEGER) * ? AS t, {', '.join(_avg(k) for k in keys)}
                    FROM history WHERE ts >= ? GROUP BY 1, 2 ORDER BY 1, 2""",
                (bucket, bucket, since),
            ).fetchall()
        hosts: dict[str, dict] = {}
        for host, t, *vals in rows:
            h = hosts.setdefault(host, {"t": [], **{k: [] for k in keys}})
            h["t"].append(t)
            for k, v in zip(keys, vals):
                h[k].append(round(v, 1) if v is not None else None)
        return {"bucket": bucket, "hosts": hosts}
