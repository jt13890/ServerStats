"""Normalizes collector payloads.

Samples come from monitored hosts, so they're untrusted: a compromised or
buggy host must not be able to break the dashboard for everyone else by
sending unexpected types or huge values. Everything is rebuilt here from
known fields with coerced types and bounded sizes.
"""

import math

MAX_DISKS = 64
MAX_DEVICES = 64


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


def normalize(d: dict, max_procs: int) -> dict:
    cpu, mem, net, tasks, dio = (_dict(d.get(k)) for k in ("cpu", "memory", "net", "tasks", "disk_io"))
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
            "percent": _num(x.get("percent")),
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
            "util": _num(x.get("util")),
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
            "cpu": _num(p.get("cpu")),
            "mem": _num(p.get("mem")),
            "rss": _num(p.get("rss")),
            "threads": _int(p.get("threads")),
            "started": _num(p.get("started")),
            "cmd": _str(p.get("cmd"), 512),
        })

    return {
        "agent_version": _str(d.get("agent_version"), 32),
        "collected_at": _num(d.get("collected_at"), None),
        "hostname": _str(d.get("hostname"), 253),
        "os": _str(d.get("os")),
        "kernel": _str(d.get("kernel")),
        "arch": _str(d.get("arch"), 32),
        "uptime": _num(d.get("uptime"), None),
        "cpu": {"count": _int(cpu.get("count"), 1), "percent": _num(cpu.get("percent"))},
        "load": load + [0.0] * (3 - len(load)),
        "memory": {k: _num(mem.get(k)) for k in ("total", "available", "used", "percent", "swap_total", "swap_used")},
        "disks": disks,
        "disk_io": {
            "read_rate": _num(dio.get("read_rate")),
            "write_rate": _num(dio.get("write_rate")),
            "util": _num(dio.get("util")),
            "devices": devices,
        },
        "net": {"rx_rate": _num(net.get("rx_rate")), "tx_rate": _num(net.get("tx_rate"))},
        "tasks": {k: _int(tasks.get(k)) for k in ("total", "running", "sleeping", "zombie", "threads")},
        "processes": processes,
    }
