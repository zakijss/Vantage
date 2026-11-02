#!/usr/bin/env python3
"""Vantage peer agent: pushes this device's stats to the dashboard.

Runs on a peer device, as a Podman container or plain python.
Reads CPU/mem/load/uptime from the container's own /proc (host-wide,
un-namespaced) and battery/temperature from a bind-mounted host /sys.
Stdlib only.
"""

import json
import os
import socket
import time
import urllib.request

DASH = os.environ.get("DASH_URL", "http://127.0.0.1:8106/api/push")
TOKEN = os.environ.get("DASH_TOKEN", "").strip()
NAME = os.environ.get("DASH_NAME", socket.gethostname())
PROC = os.environ.get("PROC_ROOT", "/proc")
SYS = os.environ.get("SYS_ROOT", "/sys")
INTERVAL = int(os.environ.get("INTERVAL", "5"))

# http and https only, so DASH_URL can't point the push at a file:// or ftp:// URL
_web = urllib.request.OpenerDirector()
for _h in (urllib.request.UnknownHandler, urllib.request.HTTPHandler, urllib.request.HTTPSHandler,
           urllib.request.HTTPRedirectHandler, urllib.request.HTTPDefaultErrorHandler,
           urllib.request.HTTPErrorProcessor):
    _web.add_handler(_h())

_cpu_prev = {"idle": 0, "total": 0}


def cpu_pct():
    try:
        with open(f"{PROC}/stat") as f:
            vals = [int(x) for x in f.readline().split()[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        d_idle = idle - _cpu_prev["idle"]
        d_total = total - _cpu_prev["total"]
        _cpu_prev.update(idle=idle, total=total)
        return round(100.0 * (1 - d_idle / d_total), 1) if d_total > 0 else 0.0
    except Exception:
        return 0.0


def snapshot():
    mem = {}
    try:
        with open(f"{PROC}/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.strip().split()[0])
    except Exception:
        pass
    try:
        with open(f"{PROC}/loadavg") as f:
            load = [float(x) for x in f.read().split()[:3]]
    except Exception:
        load = [0, 0, 0]
    try:
        with open(f"{PROC}/uptime") as f:
            uptime = float(f.read().split()[0])
    except Exception:
        uptime = 0
    temps = []
    tbase = f"{SYS}/class/thermal"
    try:
        for z in os.listdir(tbase):
            if z.startswith("thermal_zone"):
                try:
                    with open(f"{tbase}/{z}/temp") as f:
                        temps.append(int(f.read().strip()) / 1000)
                except Exception:
                    pass
    except Exception:
        pass
    bat, pbase = None, f"{SYS}/class/power_supply"
    try:
        caps = []
        for b in os.listdir(pbase):
            if b.startswith("BAT"):
                try:
                    with open(f"{pbase}/{b}/capacity") as f:
                        caps.append(int(f.read().strip()))
                except Exception:
                    pass
        if caps:
            bat = round(sum(caps) / len(caps))
    except Exception:
        pass
    return {
        "name": NAME,
        "cpu": cpu_pct(),
        "load": load,
        "uptime": uptime,
        "mem_total": mem.get("MemTotal", 0),
        "mem_avail": mem.get("MemAvailable", 0),
        "temp": round(max(temps), 1) if temps else None,
        "battery": bat,
    }


def main():
    if not TOKEN:
        raise SystemExit("DASH_TOKEN is required; set it to match the dashboard")
    cpu_pct()  # prime delta
    time.sleep(1)
    print(f"agent pushing '{NAME}' -> {DASH} every {INTERVAL}s", flush=True)
    while True:
        try:
            body = json.dumps(snapshot()).encode()
            req = urllib.request.Request(
                DASH, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "X-Dash-Token": TOKEN,
                         "User-Agent": "vantage-agent"})
            _web.open(req, timeout=8).read()
        except Exception as e:
            print(f"push failed: {e}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
