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

Docker containers are reported too when this account can read the Docker
socket (i.e. is in the docker group); set SERVERSTATS_DOCKER=0 to turn that off.
"""

import argparse
import http.client
import json
import os
import platform
import pwd
import re
import socket
import ssl
import sys
import threading
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


def _net_bytes(path="/proc/net/dev"):
    rx = tx = 0
    try:
        lines = _read(path).splitlines()[2:]
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


# -- Docker (optional) ---------------------------------------------------------
#
# Grouping containers into compose stacks needs their labels, which only the
# Docker API has. Reading it is opt-in (this account must be in the docker
# group) and only these fixed, read-only GET requests are ever sent. Resource
# usage itself comes from the containers' cgroups, not from Docker.

DOCKER_SOCK = os.environ.get("SERVERSTATS_DOCKER_SOCK", "/var/run/docker.sock")
CGROUP_ROOT = os.environ.get("SERVERSTATS_CGROUP_ROOT", "/sys/fs/cgroup")
DOCKER_DISK_EVERY = 900  # seconds between (slow) disk usage scans
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        http.client.HTTPConnection.__init__(self, "localhost", timeout=timeout)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def _docker_get(path, timeout=5):
    conn = _UnixHTTPConnection(DOCKER_SOCK, timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read(64 * 1024 * 1024)
        if resp.status != 200:
            raise OSError("Docker API returned HTTP %d for %s" % (resp.status, path))
        return json.loads(body.decode("utf-8", "replace"))
    finally:
        conn.close()


def _kv_file(path):
    out = {}
    for line in _read(path).splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[0]] = int(parts[1])
    return out


def _cgroup_counters(pid):
    """(cpu ns, memory bytes, bytes read, bytes written) for a process's cgroup."""
    v2, v1 = None, {}
    for line in _read("/proc/%d/cgroup" % pid).splitlines():
        hid, ctrls, path = line.split(":", 2)
        if hid == "0" and not ctrls:
            v2 = os.path.join(CGROUP_ROOT, path.lstrip("/"))
        for c in ctrls.split(","):
            if c:
                v1[c] = path.lstrip("/")

    if v2 and os.path.exists(os.path.join(v2, "memory.current")):  # cgroup v2
        cpu = _kv_file(os.path.join(v2, "cpu.stat")).get("usage_usec", 0) * 1000
        mem = int(_read(os.path.join(v2, "memory.current")))
        # Like `docker stats`: don't count reclaimable page cache.
        mem -= _kv_file(os.path.join(v2, "memory.stat")).get("inactive_file", 0)
        rd = wr = 0
        try:
            for line in _read(os.path.join(v2, "io.stat")).splitlines():
                for field in line.split()[1:]:
                    k, _, v = field.partition("=")
                    if k == "rbytes":
                        rd += int(v)
                    elif k == "wbytes":
                        wr += int(v)
        except OSError:
            pass
        return cpu, max(mem, 0), rd, wr

    def v1_dir(controller, *mounts):  # cgroup v1: each controller has its own tree
        for m in mounts:
            d = os.path.join(CGROUP_ROOT, m, v1.get(controller, ""))
            if os.path.isdir(d):
                return d
        raise OSError("no %s cgroup for pid %d" % (controller, pid))

    cpu = int(_read(os.path.join(v1_dir("cpuacct", "cpuacct", "cpu,cpuacct", "cpuacct,cpu"), "cpuacct.usage")))
    mdir = v1_dir("memory", "memory")
    mem = int(_read(os.path.join(mdir, "memory.usage_in_bytes")))
    mem -= _kv_file(os.path.join(mdir, "memory.stat")).get("total_inactive_file", 0)
    rd = wr = 0
    try:
        for line in _read(os.path.join(v1_dir("blkio", "blkio"), "blkio.throttle.io_service_bytes")).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "Read":
                rd += int(parts[2])
            elif len(parts) == 3 and parts[1] == "Write":
                wr += int(parts[2])
    except OSError:
        pass
    return cpu, max(mem, 0), rd, wr


class _Docker(object):
    def __init__(self):
        self.pids = {}  # container id -> (pid, host networking?)
        self.disk = None
        self._disk_thread = None

    def snapshot(self):
        """Raw per-container counters, None if Docker isn't there, or an error."""
        if os.environ.get("SERVERSTATS_DOCKER", "1") == "0":
            return None
        try:
            listed = _docker_get("/containers/json")
        except (FileNotFoundError, ConnectionRefusedError):
            return None  # Docker not installed / not running
        except PermissionError:
            return {"error": "no permission to read the Docker socket; add this account to the docker group to see containers"}
        except (OSError, ValueError) as e:
            return {"error": "Docker API error: %s" % e}

        containers = {}
        for c in listed if isinstance(listed, list) else []:
            cid = c.get("Id", "")
            if not _CONTAINER_ID.match(cid):
                continue
            try:
                if cid not in self.pids:
                    info = _docker_get("/containers/%s/json" % cid)
                    host_net = (info.get("HostConfig") or {}).get("NetworkMode") == "host"
                    self.pids[cid] = (int((info.get("State") or {}).get("Pid") or 0), host_net)
                pid, host_net = self.pids[cid]
                counters = _cgroup_counters(pid) if pid else None
                net = None if host_net or not pid else _net_bytes("/proc/%d/net/dev" % pid)
            except (OSError, ValueError):
                self.pids.pop(cid, None)
                counters = net = None
            labels = c.get("Labels") or {}
            containers[cid] = {
                "name": ((c.get("Names") or ["/?"])[0]).lstrip("/"),
                "project": labels.get("com.docker.compose.project"),
                "service": labels.get("com.docker.compose.service"),
                "image": c.get("Image"),
                "status": c.get("Status"),
                "counters": counters,
                "net": net,
                "volumes": [m.get("Name") for m in c.get("Mounts") or [] if m.get("Type") == "volume"],
            }
        for cid in list(self.pids):
            if cid not in containers:
                del self.pids[cid]
        return {"containers": containers}

    def refresh_disk_in_background(self):
        """Disk usage (`docker system df`) can take a while; poll it off-thread."""
        def loop():
            while True:
                try:
                    df = _docker_get("/system/df", timeout=300)
                    self.disk = {
                        "at": time.time(),
                        "containers": {c.get("Id"): c.get("SizeRw") or 0 for c in df.get("Containers") or []},
                        "volumes": [
                            {
                                "name": v.get("Name"),
                                "project": (v.get("Labels") or {}).get("com.docker.compose.project"),
                                "size": max((v.get("UsageData") or {}).get("Size") or 0, 0),
                            }
                            for v in df.get("Volumes") or []
                        ],
                    }
                except Exception:
                    pass
                time.sleep(DOCKER_DISK_EVERY)

        if self._disk_thread is None:
            self._disk_thread = threading.Thread(target=loop, name="docker-df", daemon=True)
            self._disk_thread.start()


_DOCKER = _Docker()


def _docker_delta(before, after, elapsed, mem_total):
    if after is None or "error" in after:
        return after
    prev = (before or {}).get("containers") or {}
    disk = _DOCKER.disk or {}
    out = []
    for cid, c in after["containers"].items():
        p = prev.get(cid) or {}
        cur, old = c["counters"], p.get("counters")
        entry = {
            "id": cid[:12], "name": c["name"], "project": c["project"], "service": c["service"],
            "image": c["image"], "status": c["status"],
            "cpu": None, "mem": None, "mem_percent": None,
            "read_rate": None, "write_rate": None, "rx_rate": None, "tx_rate": None,
            "disk": (disk.get("containers") or {}).get(cid),
        }
        if cur:
            entry["mem"] = cur[1]
            entry["mem_percent"] = round(100.0 * cur[1] / mem_total, 2) if mem_total else None
        if cur and old:
            entry["cpu"] = round(100.0 * max(cur[0] - old[0], 0) / (elapsed * 1e9), 2)  # 100% = one core
            entry["read_rate"] = max(cur[2] - old[2], 0) / elapsed
            entry["write_rate"] = max(cur[3] - old[3], 0) / elapsed
        if c["net"] and p.get("net"):
            entry["rx_rate"] = max(c["net"][0] - p["net"][0], 0) / elapsed
            entry["tx_rate"] = max(c["net"][1] - p["net"][1], 0) / elapsed
        out.append(entry)
    out.sort(key=lambda e: ((e["project"] or ""), e["name"]))
    # Anonymous volumes carry no compose label; attribute them to the stack
    # (or standalone container) that mounts them.
    owner = {}
    for c in after["containers"].values():
        for v in c["volumes"]:
            owner.setdefault(v, (c["project"], None if c["project"] else c["name"]))
    volumes = None
    if disk.get("volumes") is not None:
        volumes = []
        for v in disk["volumes"]:
            project, container = (v["project"], None) if v["project"] else owner.get(v["name"], (None, None))
            volumes.append(dict(v, project=project, container=container))
    return {"containers": out, "volumes": volumes, "disk_at": disk.get("at")}


def _snapshot():
    total, idle, btime = _cpu_times()
    return {
        "t": time.monotonic(),
        "cpu": (total, idle),
        "btime": btime,
        "procs": _proc_snapshot(),
        "net": _net_bytes(),
        "io": _diskstats(),
        "docker": _DOCKER.snapshot(),
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
    docker0, docker1 = prev["docker"], cur["docker"]
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
        "docker": _docker_delta(docker0, docker1, elapsed, mem["total"]),
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


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Treat redirects as errors: never resend the token elsewhere, and don't
    mistake an SSO login page for a successful report."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            "redirected to %s - is /api/ingest excluded from your SSO proxy?" % newurl.split("?")[0],
            headers, fp,
        )


def _post(opener, url, token, payload, timeout=15):
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
    with opener.open(req, timeout=timeout) as resp:
        resp.read()


def run_agent(args):
    if not args.url or not args.token:
        sys.exit("agent mode needs --url and --token (or SERVERSTATS_URL / SERVERSTATS_TOKEN)")
    ctx = ssl.create_default_context(cafile=args.ca_file or None)
    # The agent only ever sends data; it never acts on anything the server
    # returns, so a compromised server can't run code on this host.
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirects())
    interval = max(args.interval, 2.0)
    sample = min(args.sample, interval / 2)
    failures = 0
    snapshot = None
    _DOCKER.refresh_disk_in_background()
    print("serverstats-agent %s reporting to %s every %ss" % (VERSION, args.url, interval), flush=True)
    while True:
        started = time.monotonic()
        try:
            sample_data, snapshot = collect(sample, args.max_procs, snapshot)
            sample_data["interval"] = interval  # lets the server judge staleness
            _post(opener, args.url, args.token, sample_data)
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
