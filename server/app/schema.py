"""Normalizes collector payloads.

Samples come from monitored hosts, so they're untrusted: a compromised or
buggy host must not be able to break the dashboard for everyone else by
sending unexpected types or huge values. Everything is rebuilt here from
known fields with coerced types and bounded sizes.
"""

import math

MAX_DISKS = 64
MAX_DEVICES = 64
MAX_CONTAINERS = 500
MAX_VOLUMES = 1000


def _num(v, default=0.0):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return default
    return v


def _int(v, default=0):
    return int(_num(v, default))


def _str(v, limit=128):
    if v is None:
        return ""
    return (v if isinstance(v, str) else str(v))[:limit]


def _dict(v):
    return v if isinstance(v, dict) else {}


def _list(v):
    return v if isinstance(v, list) else []


def _opt(v):
    """A number, or None when the host couldn't measure it."""
    return _num(v, None)


def _docker(v, ncpu=1):
    if not isinstance(v, dict):
        return None
    if v.get("error"):
        return {"error": _str(v.get("error"), 300)}
    containers = []
    for c in _list(v.get("containers"))[:MAX_CONTAINERS]:
        if not isinstance(c, dict):
            continue
        containers.append({
            "id": _str(c.get("id"), 12),
            "name": _str(c.get("name")),
            "project": _str(c.get("project")) or None,
            "service": _str(c.get("service")) or None,
            "image": _str(c.get("image"), 256),
            "status": _str(c.get("status"), 64),
            **{k: _opt(c.get(k)) for k in ("cpu", "mem", "mem_percent", "read_rate", "write_rate", "rx_rate", "tx_rate", "disk")},
        })
        c2 = containers[-1]
        if c2["cpu"] is not None:
            c2["cpu"] = min(max(c2["cpu"], 0.0), 100.0 * ncpu)
        if c2["mem_percent"] is not None:
            c2["mem_percent"] = min(max(c2["mem_percent"], 0.0), 100.0)
    volumes = None
    if isinstance(v.get("volumes"), list):
        volumes = [
            {
                "name": _str(x.get("name"), 256),
                "project": _str(x.get("project")) or None,
                "container": _str(x.get("container")) or None,
                "size": _num(x.get("size")),
            }
            for x in v["volumes"][:MAX_VOLUMES]
            if isinstance(x, dict)
        ]
    return {"containers": containers, "volumes": volumes, "disk_at": _opt(v.get("disk_at"))}


def _pct(v, top=100.0):
    """A percentage clamped to 0..top (older agents could report absurd CPU%)."""
    return min(max(_num(v), 0.0), top)


def normalize(d: dict, max_procs: int) -> dict:
    cpu, mem, net, tasks, dio = (_dict(d.get(k)) for k in ("cpu", "memory", "net", "tasks", "disk_io"))
    ncpu = max(_int(cpu.get("count"), 1), 1)
    load = [_num(x) for x in _list(d.get("load"))[:3]]

    disks = []
    for x in _list(d.get("disks"))[:MAX_DISKS]:
        if not isinstance(x, dict):
            continue
        total, used = _num(x.get("total")), _num(x.get("used"))
        disks.append({
            "mount": _str(x.get("mount"), 256),
            "device": _str(x.get("device"), 256),
            "fs": _str(x.get("fs"), 32),
            "total": total,
            "used": used,
            "free": _num(x.get("free"), max(total - used, 0)),
            "percent": _pct(x.get("percent")),
        })

    devices = []
    for x in _list(dio.get("devices"))[:MAX_DEVICES]:
        if not isinstance(x, dict):
            continue
        name = _str(x.get("name"), 64)
        devices.append({
            "name": name,
            "label": _str(x.get("label"), 128) or name,
            "virtual": bool(x.get("virtual")),
            "read_rate": _num(x.get("read_rate")),
            "write_rate": _num(x.get("write_rate")),
            "util": _pct(x.get("util")),
        })

    processes = []
    for p in _list(d.get("processes"))[: max(max_procs, 1)]:
        if not isinstance(p, dict):
            continue
        processes.append({
            "pid": _int(p.get("pid")),
            "ppid": _int(p.get("ppid")),
            "name": _str(p.get("name"), 64),
            "state": _str(p.get("state"), 4),
            "user": _str(p.get("user"), 64),
            "cpu": _pct(p.get("cpu"), 100.0 * ncpu),  # 100% == one core
            "mem": _pct(p.get("mem")),
            "rss": _num(p.get("rss")),
            "threads": _int(p.get("threads")),
            "started": _num(p.get("started")),
            "cmd": _str(p.get("cmd"), 512),
        })

    interval = _num(d.get("interval"), None)
    return {
        "agent_version": _str(d.get("agent_version"), 32),
        "updates": d.get("updates") is True,  # agent accepts remote updates
        "update_failed": _str(d.get("update_failed"), 32) or None,  # version that failed to start
        # Reporting interval (agents only), clamped so a host can't claim to
        # stay "online" for days after it stops reporting.
        "interval": min(max(interval, 1.0), 3600.0) if interval is not None else None,
        "collected_at": _num(d.get("collected_at"), None),
        "hostname": _str(d.get("hostname"), 253),
        "os": _str(d.get("os")),
        "kernel": _str(d.get("kernel")),
        "arch": _str(d.get("arch"), 32),
        "uptime": _num(d.get("uptime"), None),
        "cpu": {"count": ncpu, "percent": _pct(cpu.get("percent"))},
        "load": load + [0.0] * (3 - len(load)),
        "memory": {**{k: _num(mem.get(k)) for k in ("total", "available", "used", "swap_total", "swap_used")},
                   "percent": _pct(mem.get("percent"))},
        "disks": disks,
        "disk_io": {
            "read_rate": _num(dio.get("read_rate")),
            "write_rate": _num(dio.get("write_rate")),
            "util": _pct(dio.get("util")),
            "devices": devices,
        },
        "net": {"rx_rate": _num(net.get("rx_rate")), "tx_rate": _num(net.get("tx_rate"))},
        "tasks": {k: _int(tasks.get(k)) for k in ("total", "running", "sleeping", "zombie", "threads")},
        "docker": _docker(d.get("docker"), ncpu),
        "processes": processes,
    }
