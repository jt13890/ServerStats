#!/usr/bin/env python3
"""ServerStats agent / collector.

Reads host and per-process statistics straight from /proc (or, on Windows,
from the Win32 APIs through ctypes). Standard library only, Python 3.6+, so it
runs on pretty much any Linux box or Windows machine. Windows hosts use agent
mode only (see install.ps1).

Modes:
  --once       Collect a single sample and print it as JSON to stdout.
               This is what the server runs over SSH in "ssh" mode.
  (default)    Agent mode: collect every --interval seconds and POST the
               sample to <url>/api/ingest with a bearer token.

Agent settings can come from flags or environment variables:
  SERVERSTATS_URL, SERVERSTATS_TOKEN, SERVERSTATS_INTERVAL,
  SERVERSTATS_CA_FILE, SERVERSTATS_MAX_PROCS
(or from a KEY=VALUE file given with --env-file).
On Windows, SERVERSTATS_GPU=1 starts with GPU stats on (the dashboard can toggle them).

Docker containers are reported too when this account can read the Docker
socket (i.e. is in the docker group); set SERVERSTATS_DOCKER=0 to turn that off.
"""

import argparse
import collections
import hashlib
import http.client
import json
import os
import platform
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

IS_WINDOWS = sys.platform == "win32"
if not IS_WINDOWS:
    import pwd

VERSION = "1.7.0"

if IS_WINDOWS:
    CLK_TCK = 10000000  # Windows process times are 100 ns FILETIME ticks
    PAGE_SIZE = 4096
else:
    CLK_TCK = os.sysconf("SC_CLK_TCK")
    PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

# Filesystems worth reporting. Network filesystems are deliberately left out:
# statvfs() on a dead NFS/CIFS mount can hang the collector.
REAL_FS = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat",
    "ntfs", "ntfs3", "jfs", "reiserfs", "bcachefs",
}


# -- Windows ---------------------------------------------------------------------
#
# Windows hosts use the same agent, with the same standard library only: the
# numbers come straight from Win32 APIs through ctypes instead of /proc.
# Agent (push) mode only: there is no SSH pull mode for Windows, no Docker
# section, and no remote updates (rerun install.ps1 to update).

_EPOCH_DIFF = 116444736000000000  # 100 ns ticks between 1601-01-01 and 1970-01-01


def _filetime_to_unix(ticks):
    """A Windows FILETIME (100 ns ticks since 1601) as Unix seconds."""
    return int((ticks - _EPOCH_DIFF) / 10000000) if ticks else 0


def _win_os_name(product, build, display=""):
    """'Windows 11 Pro 24H2' from the registry values.

    ProductName still says "Windows 10" on Windows 11 (Microsoft never
    changed it); builds from 22000 on are Windows 11.
    """
    name = product or "Windows"
    try:
        if int(build) >= 22000:
            name = name.replace("Windows 10", "Windows 11")
    except (TypeError, ValueError):
        pass
    return ("%s %s" % (name, display)).strip() if display else name


def _win_parse_pagefiles(raw, page_size):
    """(total, used) bytes from NtQuerySystemInformation(SystemPageFileInformation).

    The buffer is a chain of entries, each starting NextEntryOffset,
    TotalSize, TotalInUse (all 32-bit, sizes in pages).
    """
    total = used = offset = 0
    while offset + 12 <= len(raw):
        nxt, size, inuse = struct.unpack_from("<III", raw, offset)
        total += size
        used += inuse
        if not nxt:
            break
        offset += nxt
    return total * page_size, used * page_size


def _win_parse_processes(raw, base, ptr=8):
    """pid -> counters, from a SystemProcessInformation buffer (NtQuerySystemInformation
    class 5, the same call Task Manager uses).

    It carries every process's CPU time, working set, thread count, start time,
    parent and name without opening any of them, so a standard user gets the
    same numbers as an administrator. `base` is the address the buffer was
    read into (name pointers point inside it); `ptr` is the pointer size of
    the reading process.
    """
    if ptr == 8:
        o_name, o_pid, o_ppid, o_ws, fmt = 64, 80, 88, 144, "<Q"
    else:
        o_name, o_pid, o_ppid, o_ws, fmt = 60, 68, 72, 104, "<I"
    procs = {}
    offset = 0
    while offset + o_ws + ptr <= len(raw):
        nxt, threads = struct.unpack_from("<II", raw, offset)
        create, user, kern = struct.unpack_from("<qqq", raw, offset + 32)  # CreateTime, UserTime, KernelTime
        nlen = struct.unpack_from("<H", raw, offset + 56)[0]
        nbuf = struct.unpack_from(fmt, raw, offset + o_name)[0]
        pid = struct.unpack_from(fmt, raw, offset + o_pid)[0]
        ppid = struct.unpack_from(fmt, raw, offset + o_ppid)[0]
        ws = struct.unpack_from(fmt, raw, offset + o_ws)[0]
        name = ""
        start = nbuf - base
        if nlen and start >= 0 and start + nlen <= len(raw):
            name = raw[start:start + nlen].decode("utf-16-le", "replace")
        if pid:  # 0 is the System Idle Process: its "CPU" is the idle time
            procs[pid] = {"name": name, "state": "S", "ppid": ppid, "ticks": user + kern, "threads": threads,
                          "starttime": create, "started": _filetime_to_unix(create), "rss": ws,
                          "uid": "", "cmd": ""}
        if not nxt:
            break
        offset += nxt
    return procs


# GPU counters name each instance after the adapter's LUID. Per-process engine
# instances look like pid_123_luid_0x00000000_0x0000F3A5_phys_0_eng_0_engtype_3D,
# adapter memory ones like luid_0x00000000_0x0000F3A5_phys_0.
_GPU_ENGINE = re.compile(r"luid_(0x[0-9a-f]+_0x[0-9a-f]+)_phys_(\d+)_eng_(\d+)_engtype_(.+)$", re.I)
_GPU_MEM = re.compile(r"luid_(0x[0-9a-f]+_0x[0-9a-f]+)_phys_(\d+)$", re.I)


def _gpu_aggregate(engines, dedicated, shared, adapters):
    """One entry per GPU from the raw counter instances.

    engines / dedicated / shared are lists of (instance name, value);
    adapters are {"luid", "name", "mem_total"} from DXGI (empty if that
    failed: the GPUs are then named from the counters).

    Busy is what Task Manager shows: the processes using one engine are added
    up, and the GPU is as busy as its busiest engine (3D, Compute, VideoEncode...).
    """
    busy, ded, shr = {}, {}, {}
    for name, v in engines:
        m = _GPU_ENGINE.search(name)
        if m:
            engines_of = busy.setdefault(m.group(1).lower(), {})
            key = (m.group(2), m.group(3), re.sub(r"#\d+$", "", m.group(4)))
            engines_of[key] = engines_of.get(key, 0.0) + max(v, 0.0)
    for items, into in ((dedicated, ded), (shared, shr)):
        for name, v in items:
            m = _GPU_MEM.search(name)
            if m:
                into[m.group(1).lower()] = into.get(m.group(1).lower(), 0.0) + max(v, 0.0)
    known = [dict(a) for a in adapters]
    if not known:
        known = [{"luid": luid, "name": "GPU %d" % i, "mem_total": 0}
                 for i, luid in enumerate(sorted(set(busy) | set(ded) | set(shr)))]
    out = []
    for a in known:
        luid = a["luid"].lower()
        top = max(busy.get(luid, {}).items(), key=lambda kv: kv[1], default=None)
        util = min(top[1], 100.0) if top else 0.0
        out.append({
            "name": a["name"],
            "util": round(util, 1),
            "engine": top[0][2] if top and util >= 1 else "",  # what is keeping it busy
            "mem_used": ded.get(luid, 0.0),
            "mem_total": a.get("mem_total") or None,
            "shared_used": shr.get(luid),
        })
    return out


# -- Temperatures ---------------------------------------------------------------------
#
# Every sensor is {"name", "chip", "kind", "temp", "high", "crit"} in degrees C, with
# kind one of cpu / gpu / disk / board / other. Linux reads sysfs (hwmon, the files
# lm-sensors reads too), which anyone can read. Windows has no sensor access for a
# standard user beyond the ACPI thermal zones and, for NVIDIA GPUs, NVML (see _win_temps).

_TEMP_KINDS = (
    ("cpu", {"coretemp", "k10temp", "zenpower", "cpu_thermal", "cpu-thermal", "x86_pkg_temp", "bcm2835_thermal",
             "soc_thermal", "cputemp", "scpi_sensors", "armada_thermal", "sun8i_thermal", "rockchip_thermal"}, ()),
    ("gpu", {"amdgpu", "radeon", "nouveau", "nvidia", "i915", "xe"}, ()),
    ("disk", {"nvme", "drivetemp"}, ()),
    ("board", {"acpitz", "thinkpad", "dell_smm", "applesmc", "cros_ec"},
     ("pch_", "nct", "it87", "w83", "asus", "lm7", "f71", "sch5", "ite_")),
)


def _temp_kind(chip, label=""):
    c = chip.lower()
    base = re.sub(r"(_\d+)+$", "", c)  # hwmon numbers duplicate chips: acpitz_0, iwlwifi_1_3
    for kind, names, prefixes in _TEMP_KINDS:
        if c in names or base in names or (prefixes and c.startswith(prefixes)):
            return kind
    if label.lower().startswith(("core ", "package", "tctl", "tdie", "tccd", "cpu")):
        return "cpu"
    return "other"


def _millideg(path):
    """A sysfs temperature file (thousandths of a degree) as degrees C; None if unreadable or absurd."""
    try:
        t = int(_read(path).strip()) / 1000.0
    except (OSError, ValueError):
        return None
    return round(t, 1) if -40 < t < 150 else None


def _threshold(path):
    t = _millideg(path)
    return t if t and t > 0 else None


def _hwmon_temps(root="/sys/class/hwmon"):
    """Sensors from /sys/class/hwmon: CPUs, NVMe and SATA drives, GPUs, boards, Wi-Fi...

    A CPU's individual cores are folded into one "hottest core" entry so a
    64-core machine doesn't list 64 rows.
    """
    sensors = []
    try:
        dirs = sorted(os.listdir(root), key=lambda d: (len(d), d))
    except OSError:
        return sensors
    for d in dirs:
        base = os.path.join(root, d)
        try:
            chip = _read(os.path.join(base, "name")).strip() or d
            files = os.listdir(base)
        except OSError:
            continue
        nums = sorted(int(m.group(1)) for m in (re.match(r"temp(\d+)_input$", f) for f in files) if m)
        if not nums:
            continue
        model = ""
        if _temp_kind(chip) == "disk":  # which drive: NVMe and SATA expose their model next to the sensor
            try:
                model = " ".join(_read(os.path.join(base, "device", "model")).split())
            except OSError:
                pass
        cores = []
        for n in nums:
            t = _millideg(os.path.join(base, "temp%d_input" % n))
            if not t:  # unreadable, or 0: how boards (ThinkPads, say) report a sensor with nothing attached
                continue
            try:
                label = _read(os.path.join(base, "temp%d_label" % n)).strip()
            except OSError:
                label = ""
            sensor = {"chip": chip, "kind": _temp_kind(chip, label), "temp": t,
                      "high": _threshold(os.path.join(base, "temp%d_max" % n)),
                      "crit": _threshold(os.path.join(base, "temp%d_crit" % n))}
            if model:
                sensor["name"] = model if label in ("", "Composite") else "%s \u00b7 %s" % (model, label)
            else:
                sensor["name"] = label or (chip if len(nums) == 1 else "%s temp%d" % (chip, n))
            if sensor["kind"] == "cpu" and re.match(r"core \d+$", label.lower()):
                cores.append(sensor)
            else:
                sensors.append(sensor)
        if cores:
            hottest = max(cores, key=lambda c: c["temp"])
            hottest["name"] = "Cores (hottest of %d)" % len(cores) if len(cores) > 1 else hottest["name"]
            sensors.append(hottest)
    return sensors


def _thermal_zone_temps(root="/sys/class/thermal"):
    """Fallback for boards without hwmon sensors (most single-board computers have a CPU zone)."""
    sensors = []
    try:
        dirs = sorted(os.listdir(root), key=lambda d: (len(d), d))
    except OSError:
        return sensors
    for d in dirs:
        if not d.startswith("thermal_zone"):
            continue
        t = _millideg(os.path.join(root, d, "temp"))
        if not t:
            continue
        try:
            kind_name = _read(os.path.join(root, d, "type")).strip() or d
        except OSError:
            kind_name = d
        sensors.append({"name": kind_name, "chip": "thermal", "kind": _temp_kind(kind_name), "temp": t,
                        "high": None, "crit": None})
    return sensors


def _win_zone_sensors(items):
    """ACPI thermal zones from (instance, tenths of a kelvin) counter values."""
    sensors = []
    for name, tenths in items:
        t = round(tenths / 10.0 - 273.15, 1)
        if not -40 < t < 150:
            continue
        zone = name.lstrip("\\")
        if zone.upper().startswith("_TZ."):
            zone = zone[4:]
        sensors.append({"name": "ACPI thermal zone " + zone, "chip": "acpi", "kind": "board", "temp": t,
                        "high": None, "crit": None})
    return sensors


def _gpu_attach_temps(adapters, temps):
    """Give each GPU its temperature, from (name, degrees C) pairs: matched by name,
    then NVIDIA GPUs in order. Adapters without one get None."""
    left = list(temps)
    for a in adapters:
        for i, (name, t) in enumerate(left):
            if name.strip().lower() == a["name"].strip().lower():
                a["temp"] = t
                del left[i]
                break
    for a in adapters:
        if "temp" not in a and left and "nvidia" in a["name"].lower():
            a["temp"] = left.pop(0)[1]
    for a in adapters:
        a.setdefault("temp", None)


def _temps():
    """The host's temperature sensors; never raises, empty when it has none (VMs, containers)."""
    try:
        sensors = _win_temps() if IS_WINDOWS else (_hwmon_temps() or _thermal_zone_temps())
    except Exception:
        return []
    return sensors[:64]


class _LogFile(object):
    """File-like object for stdout/stderr that keeps the log from growing
    forever: at `limit` bytes it moves the log to <path>.1 and starts over.
    Windows services have no journal, so the installer points the agent here."""

    def __init__(self, path, limit=1024 * 1024):
        self.path = path
        self.limit = limit

    def write(self, text):
        try:
            if os.path.getsize(self.path) > self.limit:
                os.replace(self.path, self.path + ".1")
        except OSError:
            pass
        try:
            with open(self.path, "a", encoding="utf-8", errors="replace") as f:
                f.write(text)
        except OSError:
            pass
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False


if IS_WINDOWS:
    import ctypes
    import winreg
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _iphlp = ctypes.WinDLL("iphlpapi")
    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)

    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _H = wintypes.HANDLE
    _byref = ctypes.byref

    _k32.SetErrorMode.argtypes = [wintypes.UINT]
    _k32.GetTickCount64.restype = ctypes.c_ulonglong
    _k32.OpenProcess.restype = _H
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.CloseHandle.argtypes = [_H]
    _k32.QueryFullProcessImageNameW.argtypes = [_H, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    _k32.CreateFileW.restype = _H
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, _H]
    _k32.DeviceIoControl.argtypes = [_H, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _advapi.OpenProcessToken.argtypes = [_H, wintypes.DWORD, ctypes.POINTER(_H)]
    _advapi.GetTokenInformation.argtypes = [_H, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
    _advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
    _advapi.LookupAccountSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
                                          ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                          ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    _ntdll.NtQuerySystemInformation.restype = ctypes.c_long
    _ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                ctypes.POINTER(wintypes.ULONG)]

    # Never pop up "no disk in drive" style dialogs from a service.
    _k32.SetErrorMode(0x0001 | 0x8000)

    class _MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    class _DISK_PERFORMANCE(ctypes.Structure):
        _fields_ = [("BytesRead", ctypes.c_longlong), ("BytesWritten", ctypes.c_longlong),
                    ("ReadTime", ctypes.c_longlong), ("WriteTime", ctypes.c_longlong),
                    ("IdleTime", ctypes.c_longlong), ("ReadCount", wintypes.DWORD),
                    ("WriteCount", wintypes.DWORD), ("QueueDepth", wintypes.DWORD),
                    ("SplitCount", wintypes.DWORD), ("QueryTime", ctypes.c_longlong),
                    ("StorageDeviceNumber", wintypes.DWORD), ("StorageManagerName", ctypes.c_wchar * 8)]

    class _MIB_IF_ROW2(ctypes.Structure):
        _fields_ = [("InterfaceLuid", ctypes.c_ulonglong), ("InterfaceIndex", wintypes.ULONG),
                    ("InterfaceGuid", ctypes.c_ubyte * 16), ("Alias", ctypes.c_wchar * 257),
                    ("Description", ctypes.c_wchar * 257), ("PhysicalAddressLength", wintypes.ULONG),
                    ("PhysicalAddress", ctypes.c_ubyte * 32), ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
                    ("Mtu", wintypes.ULONG), ("Type", wintypes.ULONG), ("TunnelType", wintypes.ULONG),
                    ("MediaType", wintypes.ULONG), ("PhysicalMediumType", wintypes.ULONG),
                    ("AccessType", wintypes.ULONG), ("DirectionType", wintypes.ULONG),
                    ("InterfaceAndOperStatusFlags", ctypes.c_ubyte), ("OperStatus", wintypes.ULONG),
                    ("AdminStatus", wintypes.ULONG), ("MediaConnectState", wintypes.ULONG),
                    ("NetworkGuid", ctypes.c_ubyte * 16), ("ConnectionType", wintypes.ULONG),
                    ("TransmitLinkSpeed", ctypes.c_ulonglong), ("ReceiveLinkSpeed", ctypes.c_ulonglong),
                    ("InOctets", ctypes.c_ulonglong), ("InUcastPkts", ctypes.c_ulonglong),
                    ("InNUcastPkts", ctypes.c_ulonglong), ("InDiscards", ctypes.c_ulonglong),
                    ("InErrors", ctypes.c_ulonglong), ("InUnknownProtos", ctypes.c_ulonglong),
                    ("InUcastOctets", ctypes.c_ulonglong), ("InMulticastOctets", ctypes.c_ulonglong),
                    ("InBroadcastOctets", ctypes.c_ulonglong), ("OutOctets", ctypes.c_ulonglong),
                    ("OutUcastPkts", ctypes.c_ulonglong), ("OutNUcastPkts", ctypes.c_ulonglong),
                    ("OutDiscards", ctypes.c_ulonglong), ("OutErrors", ctypes.c_ulonglong),
                    ("OutUcastOctets", ctypes.c_ulonglong), ("OutMulticastOctets", ctypes.c_ulonglong),
                    ("OutBroadcastOctets", ctypes.c_ulonglong), ("OutQLen", ctypes.c_ulonglong)]

    class _MIB_IF_TABLE2(ctypes.Structure):
        _fields_ = [("NumEntries", wintypes.ULONG), ("Table", _MIB_IF_ROW2 * 1)]

    def _ft(ft):
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    def _win_uptime():
        return _k32.GetTickCount64() / 1000.0

    def _win_cpu_times():
        """One aggregate "cpu0" of (busy, idle, iowait) in 100 ns ticks."""
        idle, kern, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
        if not _k32.GetSystemTimes(_byref(idle), _byref(kern), _byref(user)):
            raise OSError("GetSystemTimes failed")
        i, k, u = _ft(idle), _ft(kern), _ft(user)
        # Kernel time includes the idle time.
        return {"cpu0": (max(k - i, 0) + u, i, 0)}, int(time.time() - _win_uptime())

    def _win_meminfo():
        st = _MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(st)
        if not _k32.GlobalMemoryStatusEx(_byref(st)):
            raise OSError("GlobalMemoryStatusEx failed")
        total, avail = st.ullTotalPhys, st.ullAvailPhys
        swap_total = swap_used = 0
        size = 4096
        for _ in range(4):
            buf = ctypes.create_string_buffer(size)
            need = wintypes.ULONG(0)
            status = _ntdll.NtQuerySystemInformation(0x12, buf, size, _byref(need))  # SystemPageFileInformation
            if status & 0xFFFFFFFF == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH: grow and retry
                size = max(need.value, size * 2)
                continue
            if status >= 0:
                swap_total, swap_used = _win_parse_pagefiles(buf.raw[:max(need.value, 12)], PAGE_SIZE)
            break
        return {
            "total": total,
            "available": avail,
            "used": total - avail,
            "percent": round(100.0 * (total - avail) / total, 1) if total else 0.0,
            "swap_total": swap_total,
            "swap_used": min(swap_used, swap_total),
        }

    def _win_disks():
        disks = []
        buf = ctypes.create_unicode_buffer(1024)
        n = _k32.GetLogicalDriveStringsW(1024, buf)
        if not n or n > 1024:
            return disks
        for root in buf[:n].split("\0"):
            if not root or _k32.GetDriveTypeW(root) != 3:  # fixed disks only: no optical, network or removable
                continue
            avail, total, free = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
            if not _k32.GetDiskFreeSpaceExW(root, _byref(avail), _byref(total), _byref(free)) or not total.value:
                continue  # e.g. a locked BitLocker volume
            fs = ctypes.create_unicode_buffer(64)
            if not _k32.GetVolumeInformationW(root, None, 0, None, None, None, fs, 64):
                fs.value = ""
            used = total.value - free.value
            disks.append({
                "mount": root,
                "device": root.rstrip("\\"),
                "fs": fs.value.lower(),
                "total": total.value,
                "used": used,
                "free": avail.value,
                "percent": round(100.0 * used / (used + avail.value), 1) if used + avail.value else 0.0,
            })
        return disks

    def _win_diskstats():
        """PhysicalDriveN -> (bytes read, bytes written, ms spent busy), cumulative.

        Busy time is the time the drive wasn't idle, like Task Manager's "Active
        time": the wall clock minus the drive's cumulative idle time.
        """
        out = {}
        for n in range(16):
            h = _k32.CreateFileW("\\\\.\\PhysicalDrive%d" % n, 0, 3, None, 3, 0, None)
            if h in (None, _INVALID_HANDLE):
                continue
            try:
                perf = _DISK_PERFORMANCE()
                got = wintypes.DWORD(0)
                if _k32.DeviceIoControl(h, 0x70020, None, 0, _byref(perf), ctypes.sizeof(perf), _byref(got), None):
                    out["PhysicalDrive%d" % n] = (
                        perf.BytesRead, perf.BytesWritten, max(perf.QueryTime - perf.IdleTime, 0) // 10000)
            finally:
                _k32.CloseHandle(h)
        return out

    def _win_net_bytes():
        table = ctypes.c_void_p()
        if _iphlp.GetIfTable2(_byref(table)) != 0 or not table.value:
            return 0, 0
        try:
            hdr = _MIB_IF_TABLE2.from_address(table.value)
            first = table.value + _MIB_IF_TABLE2.Table.offset
            rows = (_MIB_IF_ROW2 * hdr.NumEntries).from_address(first)
            ours, everything = [0, 0], [0, 0]
            for r in rows:
                if r.Type == 24:  # software loopback
                    continue
                everything[0] += r.InOctets
                everything[1] += r.OutOctets
                if r.InterfaceAndOperStatusFlags & 1:  # a real adapter: virtual switches and tunnels just
                    ours[0] += r.InOctets              # carry traffic that also crosses one
                    ours[1] += r.OutOctets
            return tuple(ours) if any(ours) else tuple(everything)
        finally:
            _iphlp.FreeMibTable(table)

    _win_sid_names = {}

    def _win_proc_user(handle):
        tok = _H()
        if not _advapi.OpenProcessToken(handle, 0x0008, _byref(tok)):  # TOKEN_QUERY
            return ""
        try:
            need = wintypes.DWORD(0)
            _advapi.GetTokenInformation(tok, 1, None, 0, _byref(need))  # TokenUser
            if not need.value:
                return ""
            buf = ctypes.create_string_buffer(need.value)
            if not _advapi.GetTokenInformation(tok, 1, buf, need.value, _byref(need)):
                return ""
            sid = ctypes.c_void_p.from_buffer(buf).value  # TOKEN_USER starts with the SID pointer
            key = ctypes.string_at(sid, _advapi.GetLengthSid(sid))
            if key not in _win_sid_names:
                name, dom = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
                nlen, dlen, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD(0)
                ok = _advapi.LookupAccountSidW(None, sid, name, _byref(nlen), dom, _byref(dlen), _byref(use))
                _win_sid_names[key] = name.value if ok else ""
            return _win_sid_names[key]
        finally:
            _k32.CloseHandle(tok)

    _win_extra = {}  # (pid, start) -> (user, image path), looked up once per process

    def _win_proc_details(pid):
        """(user, image path) of a process, blank when this account may not open it
        (other users' and protected processes, for a standard user)."""
        h = _k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return "", ""
        try:
            path, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
            ok = _k32.QueryFullProcessImageNameW(h, 0, path, _byref(size))
            return _win_proc_user(h), (path.value if ok else "")
        finally:
            _k32.CloseHandle(h)

    def _win_proc_snapshot():
        size = 1 << 20
        for _ in range(6):
            buf = ctypes.create_string_buffer(size)
            need = wintypes.ULONG(0)
            status = _ntdll.NtQuerySystemInformation(5, buf, size, _byref(need))  # SystemProcessInformation
            if status & 0xFFFFFFFF == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH: grow and retry
                size = max(need.value + 65536, size * 2)
                continue
            if status < 0:
                raise OSError("cannot list processes (NTSTATUS 0x%08X)" % (status & 0xFFFFFFFF))
            break
        else:
            raise OSError("the process list kept growing")
        procs = _win_parse_processes(buf.raw[:need.value or size], ctypes.addressof(buf), ctypes.sizeof(ctypes.c_void_p))
        seen = {}
        for pid, p in procs.items():
            key = (pid, p["starttime"])
            if key not in _win_extra:
                _win_extra[key] = _win_proc_details(pid)
            seen[key] = _win_extra[key]
            p["uid"], p["cmd"] = seen[key]
        _win_extra.clear()
        _win_extra.update(seen)
        return procs

    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8)]

    class _DXGI_ADAPTER_DESC1(ctypes.Structure):
        _fields_ = [("Description", ctypes.c_wchar * 128), ("VendorId", ctypes.c_uint32),
                    ("DeviceId", ctypes.c_uint32), ("SubSysId", ctypes.c_uint32), ("Revision", ctypes.c_uint32),
                    ("DedicatedVideoMemory", ctypes.c_size_t), ("DedicatedSystemMemory", ctypes.c_size_t),
                    ("SharedSystemMemory", ctypes.c_size_t), ("LuidLow", ctypes.c_uint32),
                    ("LuidHigh", ctypes.c_int32), ("Flags", ctypes.c_uint32)]

    class _PDH_ITEM(ctypes.Structure):  # PDH_FMT_COUNTERVALUE_ITEM_W with a double value
        _fields_ = [("szName", ctypes.c_wchar_p), ("CStatus", ctypes.c_uint32), ("value", ctypes.c_double)]

    _pdh = ctypes.WinDLL("pdh")
    _pdh.PdhOpenQueryW.restype = ctypes.c_long
    _pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
    _pdh.PdhAddEnglishCounterW.restype = ctypes.c_long
    _pdh.PdhAddEnglishCounterW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_size_t,
                                           ctypes.POINTER(ctypes.c_void_p)]
    _pdh.PdhCollectQueryData.restype = ctypes.c_long
    _pdh.PdhCollectQueryData.argtypes = [ctypes.c_void_p]
    _pdh.PdhGetFormattedCounterArrayW.restype = ctypes.c_long
    _pdh.PdhGetFormattedCounterArrayW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                  ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _pdh.PdhCloseQuery.argtypes = [ctypes.c_void_p]

    _gpu_adapters = []
    _gpu_adapters_done = []

    def _win_gpu_adapters():
        """Hardware GPUs from DXGI: [{"luid", "name", "mem_total"}], looked up once.

        DXGI needs no special rights, and its LUIDs are what the performance
        counters name their instances after. Software adapters (the "Microsoft
        Basic Render Driver") are left out.
        """
        if _gpu_adapters_done:
            return _gpu_adapters
        _gpu_adapters_done.append(True)
        try:
            import uuid
            dxgi = ctypes.WinDLL("dxgi")
            dxgi.CreateDXGIFactory1.restype = ctypes.c_long
            dxgi.CreateDXGIFactory1.argtypes = [ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)]
            iid = _GUID.from_buffer_copy(uuid.UUID("770aae78-f26f-4dba-a829-253c83d1b387").bytes_le)  # IDXGIFactory1
            factory = ctypes.c_void_p()
            if dxgi.CreateDXGIFactory1(_byref(iid), _byref(factory)) < 0:
                return _gpu_adapters

            def call(obj, index, argtypes, *args):  # COM method number `index` of `obj`
                vtable = ctypes.cast(ctypes.cast(obj, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
                return ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)(vtable[index])(obj, *args)

            try:
                for i in range(16):
                    adapter = ctypes.c_void_p()
                    if call(factory.value, 12, [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)],  # EnumAdapters1
                            i, _byref(adapter)) < 0:
                        break
                    try:
                        desc = _DXGI_ADAPTER_DESC1()
                        if call(adapter.value, 10, [ctypes.POINTER(_DXGI_ADAPTER_DESC1)], _byref(desc)) >= 0 \
                                and not desc.Flags & 2:  # DXGI_ADAPTER_FLAG_SOFTWARE
                            _gpu_adapters.append({
                                "luid": "0x%08x_0x%08x" % (desc.LuidHigh & 0xFFFFFFFF, desc.LuidLow),
                                "name": desc.Description.strip() or "GPU",
                                "mem_total": desc.DedicatedVideoMemory,
                            })
                    finally:
                        call(adapter.value, 2, [])  # Release
            finally:
                call(factory.value, 2, [])
        except Exception:
            pass
        return _gpu_adapters

    def _pdh_array(handle):
        """[(instance name, value)] of a wildcard counter, as doubles; [] when it has no values yet."""
        size, count = wintypes.DWORD(0), wintypes.DWORD(0)
        status = _pdh.PdhGetFormattedCounterArrayW(handle, 0x200, _byref(size), _byref(count), None)  # PDH_FMT_DOUBLE
        if status & 0xFFFFFFFF != 0x800007D2:  # PDH_MORE_DATA: anything else means no values yet
            return []
        buf = ctypes.create_string_buffer(size.value)
        if _pdh.PdhGetFormattedCounterArrayW(handle, 0x200, _byref(size), _byref(count), buf) != 0:
            return []
        items = (_PDH_ITEM * count.value).from_buffer(buf)
        return [(it.szName, it.value) for it in items if it.CStatus in (0, 1) and it.szName]

    class _WinGpuReader(object):
        """The GPU performance counters (Windows 10 1709+): per-engine busy time and
        adapter memory, for every vendor, readable without administrator rights."""

        PATHS = (("engine", "\\GPU Engine(*)\\Utilization Percentage"),
                 ("dedicated", "\\GPU Adapter Memory(*)\\Dedicated Usage"),
                 ("shared", "\\GPU Adapter Memory(*)\\Shared Usage"))

        def __init__(self):
            self.adapters = _win_gpu_adapters()
            self.query = ctypes.c_void_p()
            status = _pdh.PdhOpenQueryW(None, 0, _byref(self.query))
            if status != 0:
                raise OSError("cannot open a performance counter query (PDH 0x%08X)" % (status & 0xFFFFFFFF))
            self.counters = {}
            for key, counter_path in self.PATHS:
                handle = ctypes.c_void_p()
                status = _pdh.PdhAddEnglishCounterW(self.query, counter_path, 0, _byref(handle))
                if status != 0:
                    self.close()
                    raise OSError("this Windows has no GPU performance counters (it needs Windows 10 1709 or "
                                  "newer and a WDDM 2.0 driver); PDH 0x%08X" % (status & 0xFFFFFFFF))
                self.counters[key] = handle

        def collect(self):
            _pdh.PdhCollectQueryData(self.query)

        def read(self, key):
            return _pdh_array(self.counters[key])

        def report(self):
            return _gpu_aggregate(self.read("engine"), self.read("dedicated"), self.read("shared"), self.adapters)

        def close(self):
            if self.query:
                _pdh.PdhCloseQuery(self.query)
                self.query = ctypes.c_void_p()

    _thermal = {"reader": None, "failed": False}

    def _win_thermal_zones():
        """ACPI thermal zones from the "Thermal Zone Information" counters (readable by any user).

        These are what the firmware chooses to expose: on laptops usually a real
        CPU-area temperature, on many desktops a fixed or unrelated value, and on
        VMs nothing. CPU package and core temperatures need a kernel driver, so
        they aren't available without administrator rights.
        """
        if _thermal["failed"]:
            return []
        try:
            if _thermal["reader"] is None:
                query, handle = ctypes.c_void_p(), ctypes.c_void_p()
                if _pdh.PdhOpenQueryW(None, 0, _byref(query)) != 0:
                    raise OSError("no performance counters")
                if _pdh.PdhAddEnglishCounterW(query, "\\Thermal Zone Information(*)\\High Precision Temperature",
                                              0, _byref(handle)) != 0:
                    _pdh.PdhCloseQuery(query)
                    raise OSError("no thermal zone counters")
                _thermal["reader"] = (query, handle)
            query, handle = _thermal["reader"]
            _pdh.PdhCollectQueryData(query)
            return _win_zone_sensors(_pdh_array(handle))
        except Exception:
            _thermal["failed"] = True  # this Windows doesn't have them: don't ask again
            return []

    _nvml = {"tried": False, "lib": None, "devices": []}

    def _win_nvidia_temps():
        """[(name, degrees C)] for NVIDIA GPUs, through NVML (nvml.dll ships with the driver; no
        administrator rights needed). Nothing on machines without an NVIDIA driver."""
        st = _nvml
        if not st["tried"]:
            st["tried"] = True
            lib = None
            for candidate in ("nvml.dll", os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                                       "NVIDIA Corporation", "NVSMI", "nvml.dll")):
                try:
                    lib = ctypes.WinDLL(candidate)
                    break
                except OSError:
                    continue
            try:
                if lib is not None and lib.nvmlInit_v2() == 0:
                    count = ctypes.c_uint(0)
                    lib.nvmlDeviceGetCount_v2(_byref(count))
                    for i in range(min(count.value, 16)):
                        dev = ctypes.c_void_p()
                        if lib.nvmlDeviceGetHandleByIndex_v2(i, _byref(dev)) != 0:
                            continue
                        name = ctypes.create_string_buffer(96)
                        lib.nvmlDeviceGetName(dev, name, 96)
                        st["devices"].append((dev, name.value.decode("utf-8", "replace")))
                    st["lib"] = lib
            except Exception:
                st["devices"] = []
        out = []
        for dev, name in st["devices"]:
            t = ctypes.c_uint(0)
            if st["lib"].nvmlDeviceGetTemperature(dev, 0, _byref(t)) == 0:  # NVML_TEMPERATURE_GPU
                out.append((name, float(t.value)))
        return out

    def _win_temps():
        sensors = _win_thermal_zones()
        for name, t in _win_nvidia_temps():
            sensors.append({"name": name, "chip": "nvidia", "kind": "gpu", "temp": t, "high": None, "crit": None})
        return sensors

    def _win_os_info():
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
                def val(name):
                    try:
                        return str(winreg.QueryValueEx(k, name)[0])
                    except OSError:
                        return ""
                return _win_os_name(val("ProductName"), val("CurrentBuildNumber"),
                                    val("DisplayVersion") or val("ReleaseId"))
        except OSError:
            return "Windows"


def _read(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def _cpu_times():
    """Per-CPU jiffies keyed "cpu0", "cpu1"..., plus boot time.

    Each CPU is (busy, idle, iowait). Per CPU rather than the "cpu" summary
    line: phones and other devices that take cores offline to save power drop
    those cores from the summary, so its counters can jump backwards between
    two readings.
    """
    if IS_WINDOWS:
        return _win_cpu_times()
    cpus = {}
    btime = 0
    for line in _read("/proc/stat").splitlines():
        if line.startswith("cpu") and line[3:4].isdigit():
            name, *fields = line.split()
            vals = [int(v) for v in fields]
            vals += [0] * (8 - len(vals))
            # user nice system idle iowait irq softirq steal (guest is already in user)
            busy = vals[0] + vals[1] + vals[2] + vals[5] + vals[6] + vals[7]
            cpus[name] = (busy, vals[3], vals[4])
        elif line.startswith("btime "):
            btime = int(line.split()[1])
    return cpus, btime


def _cpu_percent(before, after):
    """Busy % across the CPUs online in both readings (0-100)."""
    busy = total = 0
    for name, (b1, i1, w1) in after.items():
        if name not in before:
            continue  # core came online in between
        b0, i0, w0 = before[name]
        db, di = b1 - b0, i1 - i0
        if db < 0 or di < 0:
            continue  # core went offline and came back: its counters restarted
        # iowait is the one counter some kernels let run backwards; ignore that.
        dw = max(w1 - w0, 0)
        busy += db
        total += db + di + dw
    return round(min(100.0 * busy / total, 100.0), 1) if total else 0.0


def _net_bytes(path="/proc/net/dev"):
    if IS_WINDOWS:
        return _win_net_bytes()
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
    if IS_WINDOWS:
        return _win_diskstats()
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
    if IS_WINDOWS:
        return name.replace("PhysicalDrive", "Disk ")
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
    if IS_WINDOWS:
        return _win_proc_snapshot()
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
    if IS_WINDOWS:
        return _win_meminfo()
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


def _oom_kills():
    """Processes the kernel has killed for lack of memory since boot (a counter), or None where unknown."""
    if IS_WINDOWS:
        return None
    try:
        for line in _read("/proc/vmstat").splitlines():
            if line.startswith("oom_kill "):
                return max(int(line.split()[1]), 0)
    except (OSError, ValueError, IndexError):
        pass
    return None


def _disks():
    if IS_WINDOWS:
        return _win_disks()
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


def _uptime():
    return _win_uptime() if IS_WINDOWS else float(_read("/proc/uptime").split()[0])


def _loadavg():
    """Load averages, or none on Windows, which has no such thing."""
    return () if IS_WINDOWS else os.getloadavg()


def _kernel():
    return platform.version() if IS_WINDOWS else platform.release()


def _os_name():
    if IS_WINDOWS:
        return _win_os_info()
    try:
        for line in _read("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


_user_cache = {}


def _user(uid):
    if isinstance(uid, str):  # Windows reports account names, not numeric ids
        return uid
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

    if v2 and os.path.exists(os.path.join(v2, "cpu.stat")):  # cgroup v2
        cpu = _kv_file(os.path.join(v2, "cpu.stat")).get("usage_usec", 0) * 1000
        try:
            mem = int(_read(os.path.join(v2, "memory.current")))
            # Like `docker stats`: don't count reclaimable page cache.
            mem = max(mem - _kv_file(os.path.join(v2, "memory.stat")).get("inactive_file", 0), 0)
        except OSError:
            mem = None  # memory controller disabled (e.g. Raspberry Pi OS default)
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
        return cpu, mem, rd, wr

    def v1_dir(controller, *mounts):  # cgroup v1: each controller has its own tree
        for m in mounts:
            d = os.path.join(CGROUP_ROOT, m, v1.get(controller, ""))
            if os.path.isdir(d):
                return d
        raise OSError("no %s cgroup for pid %d" % (controller, pid))

    cpu = int(_read(os.path.join(v1_dir("cpuacct", "cpuacct", "cpu,cpuacct", "cpuacct,cpu"), "cpuacct.usage")))
    try:
        mdir = v1_dir("memory", "memory")
        mem = int(_read(os.path.join(mdir, "memory.usage_in_bytes")))
        mem = max(mem - _kv_file(os.path.join(mdir, "memory.stat")).get("total_inactive_file", 0), 0)
    except OSError:
        mem = None  # memory controller disabled
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
    return cpu, mem, rd, wr


class _DockerReader(object):
    """Reads the Docker API directly. Used by the Docker helper service, by SSH
    mode, and by agents that were given the docker group (older --docker installs)."""

    def __init__(self):
        self.pids = {}  # container id -> (pid, host networking?)
        self.disk = None
        self._disk_thread = None

    def listing(self):
        """Running containers with just what the agent needs. Raises OSError
        (incl. FileNotFoundError / PermissionError) if Docker can't be read."""
        listed = _docker_get("/containers/json")
        out = []
        for c in listed if isinstance(listed, list) else []:
            cid = c.get("Id", "")
            if not _CONTAINER_ID.match(cid):
                continue
            if cid not in self.pids:
                try:
                    info = _docker_get("/containers/%s/json" % cid)
                except (OSError, ValueError):
                    continue
                host_net = (info.get("HostConfig") or {}).get("NetworkMode") == "host"
                self.pids[cid] = (int((info.get("State") or {}).get("Pid") or 0), host_net)
            pid, host_net = self.pids[cid]
            labels = c.get("Labels") or {}
            out.append({
                "id": cid,
                "name": ((c.get("Names") or ["/?"])[0]).lstrip("/"),
                # Only the compose labels: other labels can hold secrets.
                "project": labels.get("com.docker.compose.project"),
                "service": labels.get("com.docker.compose.service"),
                "image": c.get("Image"),
                "status": c.get("Status"),
                "pid": pid,
                "host_net": host_net,
                "volumes": [m.get("Name") for m in c.get("Mounts") or [] if m.get("Type") == "volume"],
            })
        live = set(c["id"] for c in out)
        for cid in list(self.pids):
            if cid not in live:
                del self.pids[cid]
        self.refresh_disk_in_background()
        return {"containers": out, "disk": self.disk}

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


# -- Docker helper service -----------------------------------------------------
#
# Lets the agent see containers without Docker access of its own: the installer
# runs this as a separate service (installed, root-owned code only; never a
# remote update) whose user is in the docker group. It answers each connection
# on its socket with the fixed listing above and nothing else. The socket is
# readable only by the agent's group.

DOCKER_HELPER_SOCK = os.environ.get("SERVERSTATS_DOCKER_HELPER", "/run/serverstats-docker/docker.sock")


def serve_docker_helper(path):
    reader = _DockerReader()
    try:
        os.unlink(path)
    except OSError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, 0o660)  # owner (this service) and its group (the agent) only
    server.listen(8)
    print("serverstats docker helper %s listening on %s" % (VERSION, path), flush=True)
    while True:
        conn, _ = server.accept()
        try:
            conn.settimeout(30)
            try:
                reply = reader.listing()
            except PermissionError:
                reply = {"error": "the Docker helper can't read the Docker socket (is its user in the docker group?)"}
            except (FileNotFoundError, ConnectionRefusedError):
                reply = {"error": "Docker isn't running"}
            except (OSError, ValueError) as e:
                reply = {"error": "Docker API error: %s" % e}
            conn.sendall(json.dumps(reply, separators=(",", ":")).encode())
        except OSError:
            pass
        finally:
            conn.close()


def _helper_listing():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect(DOCKER_HELPER_SOCK)
        chunks, size = [], 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 32 * 1024 * 1024:
                raise ValueError("Docker helper reply too large")
            chunks.append(chunk)
    finally:
        sock.close()
    reply = json.loads(b"".join(chunks).decode("utf-8", "replace"))
    if not isinstance(reply, dict):
        raise ValueError("unexpected reply from the Docker helper")
    return reply


class _Docker(object):
    """The agent's view of Docker: on/off (the dashboard decides), and counters."""

    def __init__(self):
        self.override = None  # set from the dashboard via the server's replies
        self.direct = _DockerReader()

    def enabled(self):
        if IS_WINDOWS:
            return False
        if self.override is not None:
            return self.override
        return os.environ.get("SERVERSTATS_DOCKER", "1") != "0"

    def status(self):
        """Lets the dashboard offer the right Docker controls for this host (none on Windows)."""
        if IS_WINDOWS:
            return None
        present = os.path.exists(DOCKER_SOCK)
        helper = os.path.exists(DOCKER_HELPER_SOCK)
        direct = present and os.access(DOCKER_SOCK, os.R_OK | os.W_OK)
        return {"present": present or helper, "available": helper or direct, "enabled": self.enabled()}

    def snapshot(self):
        """Raw per-container counters, None if off or no Docker, or an error."""
        if not self.enabled():
            return None
        try:
            if os.path.exists(DOCKER_HELPER_SOCK):
                listing = _helper_listing()
            else:
                listing = self.direct.listing()
        except (FileNotFoundError, ConnectionRefusedError):
            if os.path.exists(DOCKER_HELPER_SOCK):
                return {"error": "The ServerStats Docker helper isn't running on this host."}
            return None  # Docker not installed / not running
        except PermissionError:
            return {"error": "The agent can't read Docker yet. Rerun the installer on this host once "
                             "(it sets up read-only Docker access), then turn Docker on in the dashboard."}
        except (OSError, ValueError) as e:
            return {"error": "Docker error: %s" % e}
        if listing.get("error"):
            return {"error": str(listing["error"])}

        containers = {}
        for c in listing.get("containers") or []:
            cid = str(c.get("id", ""))
            if not _CONTAINER_ID.match(cid):
                continue
            pid = c.get("pid") if isinstance(c.get("pid"), int) else 0
            try:
                counters = _cgroup_counters(pid) if pid else None
                net = None if c.get("host_net") or not pid else _net_bytes("/proc/%d/net/dev" % pid)
            except (OSError, ValueError):
                counters = net = None
            containers[cid] = {
                "name": c.get("name"),
                "project": c.get("project"),
                "service": c.get("service"),
                "image": c.get("image"),
                "status": c.get("status"),
                "counters": counters,
                "net": net,
                "volumes": [v for v in c.get("volumes") or [] if isinstance(v, str)],
            }
        return {"containers": containers, "disk": listing.get("disk")}


_DOCKER = _Docker()


class _Gpu(object):
    """GPU stats: Windows only, and off until turned on (install with -Gpu, or use the
    dashboard). Reading them needs no administrator rights."""

    def __init__(self):
        self.override = None  # set from the dashboard via the server's replies
        self._reader = None
        self._error = None
        self._retry_at = 0.0

    def enabled(self):
        if not IS_WINDOWS:
            return False
        if self.override is not None:
            return self.override
        return os.environ.get("SERVERSTATS_GPU", "0") == "1"

    def status(self):
        """Lets the dashboard offer the GPU card and toggle: None except on Windows hosts with a GPU."""
        if not IS_WINDOWS:
            return None
        return {"present": bool(_win_gpu_adapters()), "available": True, "enabled": self.enabled()}

    def close(self):
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    def _fail(self, e):
        self.close()
        self._error = str(e) or e.__class__.__name__
        self._retry_at = time.monotonic() + 300  # try again in five minutes

    def snapshot(self):
        """Called with every sample: keeps the rate counters ticking, or lets go of them when off."""
        if not self.enabled():
            self.close()
            return
        try:
            if self._reader is None:
                if time.monotonic() < self._retry_at:
                    return
                self._reader = _WinGpuReader()
                self._error = None
                self._reader.collect()
                time.sleep(0.5)  # a rate needs two readings
            self._reader.collect()
        except Exception as e:
            self._fail(e)

    def report(self):
        """None when off, {"error"} when the counters can't be read, else {"adapters"}."""
        if not self.enabled():
            return None
        if self._reader is None:
            return {"error": self._error or "GPU counters are starting"}
        try:
            return {"adapters": self._reader.report()}
        except Exception as e:
            self._fail(e)
            return {"error": self._error}


_GPU = _Gpu()


def _docker_delta(before, after, elapsed, mem_total):
    if after is None or "error" in after:
        return after
    prev = (before or {}).get("containers") or {}
    disk = after.get("disk") or {}
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
        if cur and cur[1] is not None:
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
    cpus, btime = _cpu_times()
    return {
        "t": time.monotonic(),
        "cpu": cpus,
        "btime": btime,
        "procs": _proc_snapshot(),
        "net": _net_bytes(),
        "io": _diskstats(),
        "docker": _DOCKER.snapshot(),
        "gpu": _GPU.snapshot(),
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
    procs0, procs1 = prev["procs"], cur["procs"]
    (rx0, tx0), (rx1, tx1) = prev["net"], cur["net"]
    io0, io1 = prev["io"], cur["io"]
    docker0, docker1 = prev["docker"], cur["docker"]
    cpu0, cpu1 = prev["cpu"], cur["cpu"]
    btime = cur["btime"]

    elapsed = max(t1 - t0, 1e-6)
    ncpu = os.cpu_count() or 1
    mem = _meminfo()

    processes = []
    states = {}
    threads = 0
    for pid, p in procs1.items():
        prev = procs0.get(pid)
        dticks = p["ticks"] - prev["ticks"] if prev and prev["starttime"] == p["starttime"] else 0
        state = p["state"]
        if IS_WINDOWS:  # no per-process state there: "running" = used CPU since the last report
            state = "R" if dticks > 0 else "S"
        states[state] = states.get(state, 0) + 1
        threads += p["threads"]
        processes.append({
            "pid": pid,
            "ppid": p["ppid"],
            "name": p["name"],
            "state": state,
            "uid": p["uid"],
            # top-style: 100% == one full core
            # Against the clock, like top (100% == one full core); independent
            # of /proc/stat, so offline cores can't distort it.
            "cpu": round(min(100.0 * max(dticks, 0) / (elapsed * CLK_TCK), 100.0 * ncpu), 1),
            "rss": p["rss"],
            "mem": round(100.0 * p["rss"] / mem["total"], 1) if mem["total"] else 0.0,
            "threads": p["threads"],
            "started": p.get("started") or int(btime + p["starttime"] / CLK_TCK),
        })

    processes.sort(key=lambda p: (p["cpu"], p["rss"]), reverse=True)
    if max_procs and max_procs > 0:
        processes = processes[:max_procs]
    for p in processes:
        p["user"] = _user(p.pop("uid"))
        p["cmd"] = procs1[p["pid"]].get("cmd") or (p["name"] if IS_WINDOWS else _cmdline(p["pid"], p["name"]))

    load = _loadavg()
    temps = _temps()
    gpu = _GPU.report()
    if gpu and gpu.get("adapters"):
        _gpu_attach_temps(gpu["adapters"], [(t["name"], t["temp"]) for t in temps if t["chip"] == "nvidia"])
    return {
        "agent_version": VERSION,
        "collected_at": time.time(),
        "hostname": socket.gethostname(),
        "platform": "windows" if IS_WINDOWS else "linux",
        "os": _os_name(),
        "kernel": _kernel(),
        "arch": platform.machine(),
        "uptime": _uptime(),
        "cpu": {
            "count": ncpu,
            "percent": _cpu_percent(cpu0, cpu1),
        },
        "load": [round(x, 2) for x in load],
        "memory": mem,
        "oom_kills": _oom_kills(),
        "disks": _disks(),
        "disk_io": _disk_io(io0, io1, elapsed),
        "docker": _docker_delta(docker0, docker1, elapsed, mem["total"]),
        "docker_ctl": _DOCKER.status(),
        "gpu": gpu,
        "gpu_ctl": _GPU.status(),
        "temps": temps,
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
    """Send one report; returns the server's JSON reply (a dict, maybe empty)."""
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
        raw = resp.read(65536)
    try:
        reply = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {}
    return reply if isinstance(reply, dict) else {}


# -- remote updates ------------------------------------------------------------
#
# When you click "Update agent" in the UI, the server answers the next report
# with {"update": {"version", "sha256"}}. The agent downloads the new code from
# the same server, checks it against that hash, saves it in its own state
# directory and restarts into it. It still runs as the same unprivileged user.
# NOTE: this trusts the server - whoever controls it can push code to agents
# that have updates enabled (the default; install with --no-updates to refuse).
# The installed copy stays in place: if an update fails to start three times,
# the agent drops it and falls back to the installed version.

MAX_UPDATE_ATTEMPTS = 3
_VERSION_RE = re.compile(r'^VERSION = "([0-9.]+)"', re.M)


def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return ()


def _state_dir():
    d = os.environ.get("STATE_DIRECTORY") or os.environ.get("SERVERSTATS_STATE_DIR")
    return d.split(":")[0] if d else None


def updates_enabled():
    if IS_WINDOWS:  # os.exec* doesn't replace a process there; rerun install.ps1 to update
        return False
    d = _state_dir()
    return os.environ.get("SERVERSTATS_UPDATES", "1") != "0" and bool(d) and os.access(d, os.W_OK)


def _update_paths():
    d = _state_dir()
    return os.path.join(d, "serverstats_agent.py"), os.path.join(d, "update-attempts")


def _write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def maybe_run_updated_copy(argv):
    """At startup: hand over to a newer, downloaded copy if there is one."""
    if os.environ.get("SERVERSTATS_RUNNING_UPDATE") or not updates_enabled():
        return
    code_path, attempts_path = _update_paths()
    try:
        code = _read(code_path)
    except OSError:
        return
    m = _VERSION_RE.search(code)
    if not m or _version_tuple(m.group(1)) <= _version_tuple(VERSION):
        os.remove(code_path)  # stale: the installed version is as new or newer
        return
    try:
        attempts = int(_read(attempts_path).strip() or 0)
    except (OSError, ValueError):
        attempts = 0
    if attempts >= MAX_UPDATE_ATTEMPTS:
        print("update to %s failed to start %d times; using installed %s" % (m.group(1), attempts, VERSION),
              file=sys.stderr, flush=True)
        os.replace(code_path, code_path + ".failed")  # remembered, so it isn't retried
        return
    _write(attempts_path, str(attempts + 1))
    os.environ["SERVERSTATS_RUNNING_UPDATE"] = "1"
    os.environ.setdefault("SERVERSTATS_ENTRY", os.path.abspath(sys.argv[0]))
    os.execv(sys.executable, [sys.executable, code_path] + list(argv))


_healthy = False


def _mark_update_healthy():
    """The updated copy reported successfully: reset its failed-start count."""
    global _healthy
    if os.environ.get("SERVERSTATS_RUNNING_UPDATE") and not _healthy:
        try:
            _write(_update_paths()[1], "0")
            _healthy = True
        except OSError:
            pass


def failed_update_version():
    """Version of an update that failed to start here, if any."""
    try:
        m = _VERSION_RE.search(_read(_update_paths()[0] + ".failed"))
    except (OSError, TypeError):
        return None
    return m.group(1) if m else None


def _apply_update(opener, url, update, argv):
    version, want = str(update.get("version", "")), str(update.get("sha256", "")).lower()
    if not re.match(r"^[0-9a-f]{64}$", want) or _version_tuple(version) <= _version_tuple(VERSION):
        return
    if version == failed_update_version():
        print("not updating to %s: it failed to start here before" % version, file=sys.stderr, flush=True)
        return
    with opener.open(url.rstrip("/") + "/api/agent/serverstats_agent.py", timeout=30) as resp:
        code = resp.read(4 * 1024 * 1024)
    if hashlib.sha256(code).hexdigest() != want:
        raise ValueError("downloaded update doesn't match the announced hash")
    text = code.decode("utf-8")
    compile(text, "serverstats_agent.py", "exec")  # refuse anything that isn't valid Python
    code_path, attempts_path = _update_paths()
    _write(code_path, text)
    _write(attempts_path, "0")
    print("updating %s -> %s" % (VERSION, version), flush=True)
    entry = os.environ.get("SERVERSTATS_ENTRY") or os.path.abspath(sys.argv[0])
    env = dict(os.environ)
    env.pop("SERVERSTATS_RUNNING_UPDATE", None)
    os.execve(sys.executable, [sys.executable, entry] + list(argv), env)


# -- keeping reports while the server is away ---------------------------------
#
# When the server can't be reached the agent keeps measuring and stores a slim
# copy of each report (only what the history charts use: no processes, Docker
# or GPU data). Once a live report gets through again it sends the saved ones,
# oldest first, in chunks. It only does this if the server says it understands
# them ("backfill" in its reply to a normal report), so an older server is
# never sent something it would mistake for a live report.

BUFFER_MAX_HOURS = 48
BUFFER_MAX_ITEMS = 20000
BACKFILL_CHUNK = 500


def _slim(sample):
    """What the history charts need from a report, and nothing else."""
    dio, tasks = sample.get("disk_io") or {}, sample.get("tasks") or {}
    temps = [t for t in sample.get("temps") or []
             if isinstance(t, dict) and isinstance(t.get("temp"), (int, float))]
    pool = [t for t in temps if t.get("kind") == "cpu"] or temps  # the sensor the charts use
    return {
        "collected_at": sample.get("collected_at"),
        "interval": sample.get("interval"),
        "cpu": sample.get("cpu"),
        "memory": sample.get("memory"),
        "load": sample.get("load"),
        "net": sample.get("net"),
        "disk_io": {k: dio.get(k) for k in ("read_rate", "write_rate", "util")},
        "tasks": {k: tasks.get(k) for k in ("total", "threads")},
        "disks": [{k: d.get(k) for k in ("mount", "device", "fs", "total", "used", "free", "percent")}
                  for d in sample.get("disks") or [] if isinstance(d, dict)],
        "temps": [max(pool, key=lambda t: t["temp"])] if pool else [],
    }


class _Backlog(object):
    """A bounded queue of slim reports (oldest dropped when full), mirrored to a
    JSON-lines file readable only by this user so a restart doesn't lose it.
    Without a usable file it simply lives in memory."""

    def __init__(self, limit, path=None):
        self.limit = max(int(limit), 1)
        self.path = path
        self.items = collections.deque()
        self._lines = 0  # lines in the file, which may run a little ahead of the queue
        if path:
            self._load()

    def __len__(self):
        return len(self.items)

    def _load(self):
        try:
            with open(self.path, "r") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                self.items.append(item)
        while len(self.items) > self.limit:
            self.items.popleft()
        if len(self.items) != len(lines):  # junk or surplus lines: clean the file
            self._rewrite()
        else:
            self._lines = len(lines)

    def _rewrite(self):
        if not self.path:
            return
        try:
            if not self.items:
                self._lines = 0
                if os.path.exists(self.path):
                    os.remove(self.path)
                return
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                for item in self.items:
                    f.write(json.dumps(item, separators=(",", ":")) + "\n")
            os.replace(tmp, self.path)
            self._lines = len(self.items)
        except OSError as e:
            print("cannot save buffered reports to %s: %s (keeping them in memory)" % (self.path, e),
                  file=sys.stderr, flush=True)
            self.path = None

    def add(self, item):
        self.items.append(item)
        while len(self.items) > self.limit:
            self.items.popleft()
        if not self.path:
            return
        if self._lines >= self.limit + max(self.limit // 4, 10):
            self._rewrite()  # the file has grown well past the queue: trim it
            return
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(item, separators=(",", ":")) + "\n")
            self._lines += 1
        except OSError as e:
            print("cannot save buffered reports to %s: %s (keeping them in memory)" % (self.path, e),
                  file=sys.stderr, flush=True)
            self.path = None

    def peek(self, n):
        return list(self.items)[:n]

    def drop(self, n):
        for _ in range(min(n, len(self.items))):
            self.items.popleft()
        self._rewrite()

    def clear(self):
        self.items.clear()
        self._rewrite()


def _make_backlog(hours, interval):
    """The backlog for `hours` of reports (capped; 0 turns buffering off -> None)."""
    hours = min(max(hours, 0.0), BUFFER_MAX_HOURS)
    if hours <= 0:
        return None
    limit = max(int(min(hours * 3600.0 / interval, BUFFER_MAX_ITEMS)), 1)
    d = os.environ.get("SERVERSTATS_SPOOL_DIR") or _state_dir()
    return _Backlog(limit, os.path.join(d, "backlog.jsonl") if d else None)


def _transient(code):
    """HTTP answers that mean "the server is away", not "this report is refused"."""
    return code in (408, 425, 429) or code >= 500


def _retry_delay(failures, interval):
    """While buffering, how long to leave the server alone after a failed attempt
    (the agent still measures every interval). Same pacing as the old longer waits."""
    return 0.0 if failures < 3 else max(min(interval * failures, 300.0) - interval, 0.0)


def _flush_backlog(opener, args, backlog, takes):
    """Send one chunk of saved reports. Refused (4xx) -> dropped; not ready -> kept for next time."""
    chunk = backlog.peek(max(min(takes, BACKFILL_CHUNK), 1))
    if not chunk:
        return
    try:
        reply = _post(opener, args.url, args.token, {"backfill": chunk, "sent_at": time.time()})
    except urllib.error.HTTPError as e:
        if _transient(e.code):
            print("server not ready for buffered reports (HTTP %d); will retry" % e.code, file=sys.stderr, flush=True)
        else:
            print("server refused buffered reports (HTTP %d); dropping %d" % (e.code, len(chunk)), file=sys.stderr, flush=True)
            backlog.drop(len(chunk))
        return
    except Exception as e:
        print("sending buffered reports failed: %s; will retry" % e, file=sys.stderr, flush=True)
        return
    backlog.drop(len(chunk))
    print("sent %d buffered report(s), %d left" % (len(chunk), len(backlog)), flush=True)


def run_agent(args, argv):
    if not args.url or not args.token:
        sys.exit("agent mode needs --url and --token (or SERVERSTATS_URL / SERVERSTATS_TOKEN)")
    ctx = ssl.create_default_context(cafile=args.ca_file or None)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirects())
    interval = max(args.interval, 2.0)
    sample = min(args.sample, interval / 2)
    failures = 0
    snapshot = None
    can_update = updates_enabled()
    backlog = _make_backlog(getattr(args, "buffer_hours", 0.0), interval)
    takes = None          # reports per chunk the server accepts; None = not heard yet, 0 = it doesn't
    rejected = False      # the last answer was a refusal (bad token, login redirect...), not "away"
    next_attempt = 0.0    # while buffering: don't try the server again before this
    announced = False
    if backlog is not None and len(backlog):
        print("found %d buffered report(s) from before" % len(backlog), flush=True)
    print("serverstats-agent %s reporting to %s every %ss (remote updates %s, %s)"
          % (VERSION, args.url, interval, "on" if can_update else "off",
             "buffering up to %d reports while the server is away" % backlog.limit if backlog is not None else "no buffering"),
          flush=True)
    while True:
        started = time.monotonic()
        sample_data = None
        try:
            sample_data, snapshot = collect(sample, args.max_procs, snapshot)
            sample_data["interval"] = interval  # lets the server judge staleness
            sample_data["updates"] = can_update
            if can_update:
                sample_data["update_failed"] = failed_update_version()
            if backlog is not None and failures >= 3 and not rejected and takes != 0 and started < next_attempt:
                backlog.add(_slim(sample_data))  # still waiting before the next try
                sample_data = None
            else:
                reply = _post(opener, args.url, args.token, sample_data)
                sample_data = None  # delivered
                if failures:
                    print("reporting recovered after %d failure(s)" % failures, flush=True)
                failures, rejected, announced = 0, False, False
                _mark_update_healthy()
                takes = reply.get("backfill") if isinstance(reply.get("backfill"), int) \
                    and not isinstance(reply.get("backfill"), bool) else 0
                if backlog is not None:
                    if takes <= 0:
                        backlog.clear()  # an older server: it can't use them
                    elif len(backlog):
                        _flush_backlog(opener, args, backlog, takes)
                settings = reply.get("settings")
                if isinstance(settings, dict) and isinstance(settings.get("docker"), bool):
                    if _DOCKER.override != settings["docker"]:
                        print("Docker stats turned %s from the dashboard" % ("on" if settings["docker"] else "off"), flush=True)
                    _DOCKER.override = settings["docker"]
                if isinstance(settings, dict) and isinstance(settings.get("gpu"), bool):
                    if _GPU.override != settings["gpu"]:
                        print("GPU stats turned %s from the dashboard" % ("on" if settings["gpu"] else "off"), flush=True)
                    _GPU.override = settings["gpu"]
                if can_update and isinstance(reply.get("update"), dict):
                    try:
                        _apply_update(opener, args.url, reply["update"], argv)
                    except Exception as e:
                        print("update failed: %s" % e, file=sys.stderr, flush=True)
        except urllib.error.HTTPError as e:
            failures += 1
            rejected = not _transient(e.code)
            print("server rejected report: HTTP %d %s" % (e.code, e.reason), file=sys.stderr, flush=True)
            if e.code in (401, 403):
                print("check the token and that /api/ingest bypasses the auth proxy", file=sys.stderr, flush=True)
        except Exception as e:  # network errors, DNS, TLS...
            failures += 1
            rejected = False
            print("report failed: %s" % e, file=sys.stderr, flush=True)
        if sample_data is not None and backlog is not None and not rejected and takes != 0:
            # An attempt to reach the server just failed: keep this report, try again later.
            if not announced:
                print("buffering reports until the server is back", flush=True)
                announced = True
            backlog.add(_slim(sample_data))
            next_attempt = time.monotonic() + _retry_delay(failures, interval)
        buffering = backlog is not None and failures and not rejected and takes != 0
        # Without buffering: back off gently while the server is unreachable (max 5 minutes).
        # With it we keep measuring every interval and just try the server less often.
        wait = interval if buffering or failures < 3 else min(interval * failures, 300)
        time.sleep(max(wait - (time.monotonic() - started), 0.5))


def enroll(url, name, ca_file=None):
    """Join the server with the join key (SERVERSTATS_JOIN_KEY); print "name token"."""
    key = os.environ.get("SERVERSTATS_JOIN_KEY", "")
    if not url or not key:
        sys.exit("enrolling needs --url and SERVERSTATS_JOIN_KEY")
    ctx = ssl.create_default_context(cafile=ca_file or None)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirects())
    body = json.dumps({"key": key, "name": name, "hostname": socket.gethostname()}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/api/enroll", data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "serverstats-agent/" + VERSION},
    )
    try:
        with opener.open(req, timeout=30) as resp:
            reply = json.loads(resp.read(65536).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read(65536).decode("utf-8", "replace")).get("detail")
        except Exception:
            detail = e.reason
        sys.exit("joining failed: HTTP %d %s" % (e.code, detail))
    except Exception as e:
        sys.exit("joining failed: %s" % e)
    if not isinstance(reply, dict) or not re.match(r"^[0-9a-f]{64}$", str(reply.get("token", ""))):
        sys.exit("joining failed: unexpected reply from server")
    print("%s %s" % (reply["name"], reply["token"]))


def _load_env_file(argv):
    """Apply KEY=VALUE lines from --env-file PATH before reading settings.

    Used under OpenRC, where the token must not appear on the command line
    (visible in `ps`); the file is readable only by root and the agent user.
    Variables already set in the environment win.
    """
    path = None
    for i, a in enumerate(argv):
        if a == "--env-file" and i + 1 < len(argv):
            path = argv[i + 1]
        elif a.startswith("--env-file="):
            path = a.split("=", 1)[1]
    if not path:
        return
    try:
        lines = _read(path).splitlines()
    except OSError as e:
        sys.exit("cannot read --env-file %s: %s" % (path, e))
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


def main():
    _load_env_file(sys.argv[1:])
    env = os.environ.get
    ap = argparse.ArgumentParser(description="ServerStats agent / collector")
    ap.add_argument("--env-file", help="read SERVERSTATS_* settings from this KEY=VALUE file")
    ap.add_argument("--once", action="store_true", help="print one JSON sample to stdout and exit")
    ap.add_argument("--docker-helper", nargs="?", const=DOCKER_HELPER_SOCK, metavar="SOCKET",
                    help="run the Docker helper service (needs Docker access) on SOCKET")
    ap.add_argument("--enroll", metavar="NAME", help="join the server as NAME using SERVERSTATS_JOIN_KEY, print 'name token'")
    ap.add_argument("--url", default=env("SERVERSTATS_URL"), help="server base URL, e.g. https://stats.example.com")
    ap.add_argument("--token", default=env("SERVERSTATS_TOKEN"), help="per-host token from the server config")
    ap.add_argument("--interval", type=float, default=float(env("SERVERSTATS_INTERVAL", "15")), help="seconds between reports")
    ap.add_argument("--sample", type=float, default=1.0, help="CPU sampling window in seconds")
    ap.add_argument("--max-procs", type=int, default=int(env("SERVERSTATS_MAX_PROCS", "500")), help="report at most N processes (0 = all)")
    ap.add_argument("--buffer-hours", type=float, default=float(env("SERVERSTATS_BUFFER_HOURS", "24")),
                    help="keep this many hours of reports while the server is away, up to 48 (0 = don't)")
    ap.add_argument("--ca-file", default=env("SERVERSTATS_CA_FILE"), help="custom CA bundle for self-signed setups")
    ap.add_argument("--log-file", default=env("SERVERSTATS_LOG_FILE"),
                    help="agent mode: write output to this file (rotated at 1 MB) instead of stdout/stderr")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    if args.docker_helper:
        # Always the installed code: the helper never runs a remote update.
        serve_docker_helper(args.docker_helper)
        return
    if args.enroll:
        enroll(args.url, args.enroll, args.ca_file)
        return
    if args.once:
        json.dump(collect(args.sample, args.max_procs)[0], sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return
    if args.log_file:
        sys.stdout = sys.stderr = _LogFile(args.log_file)
    maybe_run_updated_copy(sys.argv[1:])
    try:
        run_agent(args, sys.argv[1:])
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
