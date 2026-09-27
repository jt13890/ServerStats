"""Latest-sample cache plus a small SQLite history of host-level metrics."""

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

# Filesystem usage changes slowly; record it at most this often per host.
STORAGE_SAMPLE_SECONDS = 300


@dataclass
class HostState:
    data: dict | None = None
    received_at: float | None = None
    error: str | None = None
    error_at: float | None = None
    host_key: str | None = None  # SSH host key fingerprint seen on last connect


class Store:
    def __init__(self, db_path: Path, history_hours: float):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.history_hours = history_hours
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS history (
                host TEXT NOT NULL, ts REAL NOT NULL,
                cpu REAL, mem REAL, load1 REAL, rx REAL, tx REAL,
                disk_util REAL, disk_read REAL, disk_write REAL
            );
            CREATE INDEX IF NOT EXISTS history_host_ts ON history(host, ts);
            CREATE TABLE IF NOT EXISTS storage_history (
                host TEXT NOT NULL, ts REAL NOT NULL, mount TEXT NOT NULL,
                used REAL NOT NULL, total REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS storage_host_ts ON storage_history(host, ts);
            CREATE TABLE IF NOT EXISTS latest (
                host TEXT PRIMARY KEY, received_at REAL NOT NULL, data TEXT NOT NULL
            );
            """
        )
        self.states: dict[str, HostState] = {}
        self._storage_last: dict[str, float] = {}
        for host, received_at, data in self._db.execute("SELECT host, received_at, data FROM latest"):
            self.states[host] = HostState(data=json.loads(data), received_at=received_at)

    def state(self, host: str) -> HostState:
        return self.states.setdefault(host, HostState())

    def record(self, host: str, data: dict) -> None:
        now = time.time()
        st = self.state(host)
        st.data, st.received_at, st.error, st.error_at = data, now, None, None
        net = data.get("net") or {}
        dio = data.get("disk_io") or {}
        load = data.get("load") or [None]
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO history (host, ts, cpu, mem, load1, rx, tx, disk_util, disk_read, disk_write)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    host, now,
                    (data.get("cpu") or {}).get("percent"),
                    (data.get("memory") or {}).get("percent"),
                    load[0], net.get("rx_rate"), net.get("tx_rate"),
                    dio.get("util"), dio.get("read_rate"), dio.get("write_rate"),
                ),
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

    def history(self, host: str, hours: float, points: int = 240) -> dict:
        hours = min(max(hours, 0.1), self.history_hours)
        since = time.time() - hours * 3600
        bucket = max(hours * 3600 / points, 1)
        with self._lock:
            rows = self._db.execute(
                """
                SELECT CAST(ts / ? AS INTEGER) * ? AS t,
                       AVG(cpu), AVG(mem), AVG(load1), AVG(rx), AVG(tx),
                       AVG(disk_util), AVG(disk_read), AVG(disk_write)
                FROM history WHERE host = ? AND ts >= ?
                GROUP BY 1 ORDER BY 1
                """,
                (bucket, bucket, host, since),
            ).fetchall()
            # Storage is sampled sparsely; use coarser buckets so each has data.
            sbucket = max(bucket, STORAGE_SAMPLE_SECONDS)
            srows = self._db.execute(
                """
                SELECT CAST(ts / ? AS INTEGER) * ? AS t, mount, AVG(used), AVG(total)
                FROM storage_history WHERE host = ? AND ts >= ?
                GROUP BY 1, 2 ORDER BY 1
                """,
                (sbucket, sbucket, host, since - sbucket),
            ).fetchall()
        keys = ("t", "cpu", "mem", "load1", "rx", "tx", "disk_util", "disk_read", "disk_write")
        metrics = [{k: (round(v, 2) if isinstance(v, float) else v) for k, v in zip(keys, row)} for row in rows]
        storage: dict[str, list] = {}
        for t, mount, used, total in srows:
            storage.setdefault(mount, []).append({"t": t, "used": used, "total": total})
        return {"bucket": bucket, "metrics": metrics, "storage": storage}

    def prune(self, known_hosts: set[str]) -> None:
        cutoff = time.time() - self.history_hours * 3600
        with self._lock, self._db:
            self._db.execute("DELETE FROM history WHERE ts < ?", (cutoff,))
            self._db.execute("DELETE FROM storage_history WHERE ts < ?", (cutoff,))
            # Drop data for hosts that were removed from the config.
            for (host,) in self._db.execute("SELECT DISTINCT host FROM latest").fetchall():
                if host not in known_hosts:
                    self._db.execute("DELETE FROM latest WHERE host = ?", (host,))
                    self._db.execute("DELETE FROM history WHERE host = ?", (host,))
                    self._db.execute("DELETE FROM storage_history WHERE host = ?", (host,))
                    self.states.pop(host, None)
