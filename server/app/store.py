"""Latest-sample cache plus SQLite history of host-level metrics.

History is kept in tiers so a year of it stays small:

  history      every sample (~15s)       kept RAW_DAYS
  history_5m   5-minute averages         kept M5_DAYS
  history_1h   1-hour averages           kept retention_days

A background job rolls samples up into the coarser tiers; queries pick the
coarsest tier that still has enough detail for the requested range and fill
in the not-yet-rolled-up recent part from the finer tiers.
"""

import json
import sqlite3
import threading
import time
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
# Tiers from finest to coarsest: (table, resolution seconds, rollup marker).
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


class Store:
    def __init__(self, db_path: Path, retention_days: float):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
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
            self._db.execute(
                "INSERT OR REPLACE INTO latest (host, received_at, data) VALUES (?,?,?)",
                (host, now, json.dumps(data, separators=(",", ":"))),
            )

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

    def remove_host(self, name: str) -> None:
        """Forget an enrolled host and all of its data."""
        with self._lock, self._db:
            for table in ("enrolled", "latest", "history", "history_5m", "history_1h", "storage_history", "storage_1h"):
                self._db.execute(f"DELETE FROM {table} WHERE {'name' if table == 'enrolled' else 'host'} = ?", (name,))
        self.states.pop(name, None)

    # -- rollups and retention ----------------------------------------------

    def _mark(self, key: str) -> float:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else 0.0

    def _set_mark(self, key: str, value: float) -> None:
        self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def rollup(self, now: float | None = None) -> None:
        """Average finished periods into the coarser tiers. Safe to re-run."""
        now = time.time() if now is None else now
        avgs = ", ".join(f"AVG({m})" for m in METRICS)
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

    def prune(self, known_hosts: set[str], now: float | None = None) -> None:
        now = time.time() if now is None else now
        keep = self.retention_days * DAY
        with self._lock, self._db:
            # Never drop fine-grained rows that haven't been rolled up yet.
            cutoffs = {
                "history": min(now - RAW_DAYS * DAY, self._mark("m5")),
                "history_5m": min(now - M5_DAYS * DAY, self._mark("h1")),
                "history_1h": now - keep,
                "storage_history": min(now - M5_DAYS * DAY, self._mark("s1h")),
                "storage_1h": now - keep,
            }
            for table, cutoff in cutoffs.items():
                self._db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
            # Drop data for hosts that were removed from the config.
            for (host,) in self._db.execute("SELECT DISTINCT host FROM latest").fetchall():
                if host not in known_hosts:
                    for table in ("latest", *cutoffs):
                        self._db.execute(f"DELETE FROM {table} WHERE host = ?", (host,))
                    self.states.pop(host, None)

    # -- reads --------------------------------------------------------------

    def _union(self, tiers, bucket: float, host: str, since: float, columns: str):
        """SQL + params selecting `columns` for one host from the coarsest tier
        whose resolution fits `bucket`, plus finer tiers for the recent part
        that hasn't been rolled up yet."""
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
        return " UNION ALL ".join(parts), params

    def history(self, host: str, hours: float, points: int = 240) -> dict:
        hours = min(max(hours, 0.1), self.retention_days * 24)
        now = time.time()
        since = now - hours * 3600
        bucket = max(hours * 3600 / points, 1)
        sbucket = max(bucket, STORAGE_SAMPLE_SECONDS)
        with self._lock:
            union, params = self._union(TIERS, bucket, host, since, ", ".join(METRICS))
            rows = self._db.execute(
                f"""SELECT CAST(ts / ? AS INTEGER) * ? AS t, {', '.join(f'AVG({m})' for m in METRICS)}
                    FROM ({union}) GROUP BY 1 ORDER BY 1""",
                (bucket, bucket, *params),
            ).fetchall()
            union, params = self._union(STORAGE_TIERS, sbucket, host, since - sbucket, "mount, used, total")
            srows = self._db.execute(
                f"""SELECT CAST(ts / ? AS INTEGER) * ? AS t, mount, AVG(used), AVG(total)
                    FROM ({union}) GROUP BY 1, 2 ORDER BY 1""",
                (sbucket, sbucket, *params),
            ).fetchall()
        keys = ("t", *METRICS)
        metrics = [{k: (round(v, 2) if isinstance(v, float) else v) for k, v in zip(keys, row)} for row in rows]
        storage: dict[str, list] = {}
        for t, mount, used, total in srows:
            storage.setdefault(mount, []).append({"t": t, "used": used, "total": total})
        return {"bucket": bucket, "metrics": metrics, "storage": storage}

    def trends(self, hours: float = 1.0, points: int = 60) -> dict:
        """Recent CPU/memory/disk/storage for every host (overview sparklines)."""
        bucket = max(hours * 3600 / points, 1)
        since = time.time() - hours * 3600
        keys = ("cpu", "mem", "disk_util", "storage")
        with self._lock:
            rows = self._db.execute(
                f"""SELECT host, CAST(ts / ? AS INTEGER) * ? AS t, {', '.join(f'AVG({k})' for k in keys)}
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
