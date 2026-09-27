#!/usr/bin/env python3
"""ServerStats agent / collector.

Reads host and per-process statistics straight from /proc. Standard library
only, Python 3.6+, so it runs on pretty much any Linux box.

Modes:
  --once       Collect a single sample and print it as JSON to stdout.
               This is what the server runs over SSH in "ssh" mode.
  (default)    Agent mode: collect every --interval seconds and POST the
               sample to <url>/api/ingest with a bearer token.

Agent settings can come from flags or environment variables:
  SERVERSTATS_URL, SERVERSTATS_TOKEN, SERVERSTATS_INTERVAL,
  SERVERSTATS_CA_FILE, SERVERSTATS_MAX_PROCS
"""

import argparse
import json
import os
import platform
import pwd
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0.0"

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

# Filesystems worth reporting. Network filesystems are deliberately left out:
# statvfs() on a dead NFS/CIFS mount can hang the collector.
REAL_FS = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat",
    "ntfs", "ntfs3", "jfs", "reiserfs", "bcachefs",
}


def _read(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def _cpu_times():
    """Return (total, idle) jiffies summed across all CPUs, plus boot time."""
    total = idle = 0
    btime = 0
    for line in _read("/proc/stat").splitlines():
        if line.startswith("cpu "):
            vals = [int(v) for v in line.split()[1:]]
            # user nice system idle iowait irq softirq steal (guest is already in user)
            total = sum(vals[:8])
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        elif line.startswith("btime "):
            btime = int(line.split()[1])
    return total, idle, btime


def _net_bytes():
    rx = tx = 0
    try:
        lines = _read("/proc/net/dev").splitlines()[2:]
    except OSError:
        return 0, 0
    for line in lines:
        name, _, data = line.partition(":")
        name = name.strip()
        if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr")):
            continue
        fields = data.split()
        if len(fields) >= 9:
            rx += int(fields[0])
            tx += int(fields[8])
    return rx, tx


# Block devices that never represent real disk activity.
SKIP_BLOCK = ("loop", "ram", "zram", "fd", "sr", "nbd")


def _diskstats():
    """Map whole block device -> (bytes read, bytes written, ms spent doing I/O)."""
    try:
        whole = set(os.listdir("/sys/block"))
    except OSError:
        whole = None
    out = {}
    try:
        lines = _read("/proc/diskstats").splitlines()
    except OSError:
        return out
    for line in lines:
        f = line.split()
        if len(f) < 14:
            continue
        name = f[2]
        if name.startswith(SKIP_BLOCK) or (whole is not None and name not in whole):
            continue  # pseudo device or a partition (partitions aren't in /sys/block)
        # diskstats sectors are always 512 bytes regardless of the device.
        out[name] = (int(f[5]) * 512, int(f[9]) * 512, int(f[12]))
    return out


def _block_label(name):
    """Human name for device-mapper / md devices (e.g. dm-0 -> vg-root)."""
    try:
        return _read("/sys/block/%s/dm/name" % name).strip() or name
    except OSError:
        return name


def _disk_io(before, after, elapsed):
    devices = []
    for name, (r1, w1, io1) in sorted(after.items()):
        prev = before.get(name)
        if prev is None or (r1 == 0 and w1 == 0 and io1 == 0):
            continue  # new or never-used device
        devices.append({
            "name": name,
            "label": _block_label(name),
            # dm/md sit on top of physical disks; exclude them from totals so
            # the same I/O isn't counted twice.
            "virtual": name.startswith(("dm-", "md")),
            "read_rate": max(r1 - prev[0], 0) / elapsed,
            "write_rate": max(w1 - prev[1], 0) / elapsed,
            "util": round(min(100.0, 100.0 * max(io1 - prev[2], 0) / (elapsed * 1000)), 1),
        })
    physical = [d for d in devices if not d["virtual"]] or devices
    return {
        "read_rate": sum(d["read_rate"] for d in physical),
        "write_rate": sum(d["write_rate"] for d in physical),
        "util": max([d["util"] for d in physical] or [0.0]),
        "devices": devices,
    }


def _proc_snapshot():
    """Map pid -> raw per-process counters from /proc/<pid>/stat."""
    procs = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = _read("/proc/%s/stat" % entry)
            uid = os.stat("/proc/%s" % entry).st_uid
        except OSError:
            continue  # process exited mid-scan
        # comm is wrapped in parens and may itself contain spaces or parens.
        lp, rp = stat.find("("), stat.rfind(")")
        comm = stat[lp + 1:rp]
        rest = stat[rp + 2:].split()
        try:
            procs[int(entry)] = {
                "name": comm,
                "state": rest[0],
                "ppid": int(rest[1]),
                "ticks": int(rest[11]) + int(rest[12]),  # utime + stime
                "threads": int(rest[17]),
                "starttime": int(rest[19]),
                "rss": int(rest[21]) * PAGE_SIZE,
                "uid": uid,
            }
        except (IndexError, ValueError):
            continue
    return procs


def _cmdline(pid, fallback):
    try:
        raw = _read("/proc/%d/cmdline" % pid)
    except OSError:
        raw = ""
    cmd = raw.replace("\x00", " ").strip()
    if not cmd:
        return "[%s]" % fallback  # kernel thread
    return cmd[:512]


def _meminfo():
    info = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, val = line.partition(":")
        parts = val.split()
        if parts:
            info[key] = int(parts[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    swap_total = info.get("SwapTotal", 0)
    swap_used = swap_total - info.get("SwapFree", 0)
    return {
        "total": total,
        "available": avail,
        "used": total - avail,
        "percent": round(100.0 * (total - avail) / total, 1) if total else 0.0,
        "swap_total": swap_total,
        "swap_used": swap_used,
    }


def _disks():
    disks, seen = [], set()
    try:
        mounts = _read("/proc/mounts").splitlines()
    except OSError:
        return disks
    for line in mounts:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mount, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
        if fstype not in REAL_FS or dev in seen:
            continue
        seen.add(dev)
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total == 0:
            continue
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        disks.append({
            "mount": mount,
            "device": dev,
            "fs": fstype,
            "total": total,
            "used": used,
            "free": free,
            "percent": round(100.0 * used / (used + free), 1) if used + free else 0.0,
        })
    return disks


def _os_name():
    try:
        for line in _read("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


_user_cache = {}


def _user(uid):
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _user_cache[uid] = str(uid)
    return _user_cache[uid]


def _snapshot():
    total, idle, btime = _cpu_times()
    return {
        "t": time.monotonic(),
        "cpu": (total, idle),
        "btime": btime,
        "procs": _proc_snapshot(),
        "net": _net_bytes(),
        "io": _diskstats(),
    }


def collect(sample_seconds=1.0, max_procs=500, prev=None):
    """Compute stats as deltas between two snapshots.

    With `prev` (agent mode) rates are averaged over the whole time since the
    previous report; without it we sample for `sample_seconds`.
    Returns (sample, snapshot) - pass the snapshot back in next time.
    """
    if prev is None:
        prev = _snapshot()
        time.sleep(sample_seconds)
    cur = _snapshot()

    t0, t1 = prev["t"], cur["t"]
    total0, idle0 = prev["cpu"]
    total1, idle1 = cur["cpu"]
    procs0, procs1 = prev["procs"], cur["procs"]
    (rx0, tx0), (rx1, tx1) = prev["net"], cur["net"]
    io0, io1 = prev["io"], cur["io"]
    btime = cur["btime"]

    elapsed = max(t1 - t0, 1e-6)
    dtotal = max(total1 - total0, 1)
    ncpu = os.cpu_count() or 1
    mem = _meminfo()

    processes = []
    states = {}
    threads = 0
    for pid, p in procs1.items():
        states[p["state"]] = states.get(p["state"], 0) + 1
        threads += p["threads"]
        prev = procs0.get(pid)
        dticks = p["ticks"] - prev["ticks"] if prev and prev["starttime"] == p["starttime"] else 0
        processes.append({
            "pid": pid,
            "ppid": p["ppid"],
            "name": p["name"],
            "state": p["state"],
            "uid": p["uid"],
            # top-style: 100% == one full core
            "cpu": round(100.0 * ncpu * max(dticks, 0) / dtotal, 1),
            "rss": p["rss"],
            "mem": round(100.0 * p["rss"] / mem["total"], 1) if mem["total"] else 0.0,
            "threads": p["threads"],
            "started": int(btime + p["starttime"] / CLK_TCK),
        })

    processes.sort(key=lambda p: (p["cpu"], p["rss"]), reverse=True)
    if max_procs and max_procs > 0:
        processes = processes[:max_procs]
    for p in processes:
        p["user"] = _user(p.pop("uid"))
        p["cmd"] = _cmdline(p["pid"], p["name"])

    load = os.getloadavg()
    return {
        "agent_version": VERSION,
        "collected_at": time.time(),
        "hostname": socket.gethostname(),
        "os": _os_name(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "uptime": float(_read("/proc/uptime").split()[0]),
        "cpu": {
            "count": ncpu,
            "percent": round(100.0 * (1 - (idle1 - idle0) / dtotal), 1),
        },
        "load": [round(x, 2) for x in load],
        "memory": mem,
        "disks": _disks(),
        "disk_io": _disk_io(io0, io1, elapsed),
        "net": {
            "rx_rate": max(rx1 - rx0, 0) / elapsed,
            "tx_rate": max(tx1 - tx0, 0) / elapsed,
        },
        "tasks": {
            "total": len(procs1),
            "running": states.get("R", 0),
            "sleeping": states.get("S", 0) + states.get("I", 0),
            "zombie": states.get("Z", 0),
            "threads": threads,
        },
        "processes": processes,
    }, cur


def _post(url, token, payload, ctx, timeout=15):
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/api/ingest",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "User-Agent": "serverstats-agent/" + VERSION,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        resp.read()


def run_agent(args):
    if not args.url or not args.token:
        sys.exit("agent mode needs --url and --token (or SERVERSTATS_URL / SERVERSTATS_TOKEN)")
    ctx = ssl.create_default_context(cafile=args.ca_file or None)
    interval = max(args.interval, 2.0)
    sample = min(args.sample, interval / 2)
    failures = 0
    snapshot = None
    print("serverstats-agent %s reporting to %s every %ss" % (VERSION, args.url, interval), flush=True)
    while True:
        started = time.monotonic()
        try:
            sample_data, snapshot = collect(sample, args.max_procs, snapshot)
            _post(args.url, args.token, sample_data, ctx)
            if failures:
                print("reporting recovered after %d failure(s)" % failures, flush=True)
            failures = 0
        except urllib.error.HTTPError as e:
            failures += 1
            print("server rejected report: HTTP %d %s" % (e.code, e.reason), file=sys.stderr, flush=True)
            if e.code in (401, 403):
                print("check the token and that /api/ingest bypasses the auth proxy", file=sys.stderr, flush=True)
        except Exception as e:  # network errors, DNS, TLS...
            failures += 1
            print("report failed: %s" % e, file=sys.stderr, flush=True)
        # Back off gently while the server is unreachable (max 5 minutes).
        wait = interval if failures < 3 else min(interval * failures, 300)
        time.sleep(max(wait - (time.monotonic() - started), 0.5))


def main():
    env = os.environ.get
    ap = argparse.ArgumentParser(description="ServerStats agent / collector")
    ap.add_argument("--once", action="store_true", help="print one JSON sample to stdout and exit")
    ap.add_argument("--url", default=env("SERVERSTATS_URL"), help="server base URL, e.g. https://stats.example.com")
    ap.add_argument("--token", default=env("SERVERSTATS_TOKEN"), help="per-host token from the server config")
    ap.add_argument("--interval", type=float, default=float(env("SERVERSTATS_INTERVAL", "15")), help="seconds between reports")
    ap.add_argument("--sample", type=float, default=1.0, help="CPU sampling window in seconds")
    ap.add_argument("--max-procs", type=int, default=int(env("SERVERSTATS_MAX_PROCS", "500")), help="report at most N processes (0 = all)")
    ap.add_argument("--ca-file", default=env("SERVERSTATS_CA_FILE"), help="custom CA bundle for self-signed setups")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    if args.once:
        json.dump(collect(args.sample, args.max_procs)[0], sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return
    try:
        run_agent(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
