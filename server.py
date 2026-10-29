#!/usr/bin/env python3
"""Vantage, a watch-only ops console for a self-hosted server and its tailnet.

Background threads refresh the status, the feeds and the map layers, so a
request only reads a cache. README.md lists the endpoints and settings.
"""

import datetime
import email.utils
import glob
import gzip
import hmac
import http.client
import json
import os
import re
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import alerts
import beszel
import briefing
import cables
import config
import flights
import imagery
import recon
import security
import store
import threatintel

PORT = int(os.environ.get("PORT", "8106"))
# 0.0.0.0 so a container's published port reaches it; 127.0.0.1 on a bare host
BIND = os.environ.get("BIND", "0.0.0.0")
TOKEN = os.environ.get("DASH_TOKEN", "").strip()
CACHE_TTL = 4           # seconds between status refreshes
SERVICE_EVERY = 30      # seconds between service checks: each is a line in that
                        # service's own log, and alerts wait 10 minutes anyway
CHECK_TIMEOUT = 3
PEER_STALE = 20         # seconds without a push before a peer reads as stale
HOST_SYS = os.environ.get("HOST_SYS", "/host/sys")
HOST_PROC = os.environ.get("HOST_PROC", "/host/proc")
HISTORY_LEN = 180       # samples kept for the charts


def _service(d):
    """One entry of the config's services list, with its defaults."""
    return {"name": d["name"], "port": int(d["port"]), "path": d.get("path", "/"),
            "ok": set(d.get("ok", [])), "public": d.get("public"), "host": d.get("host"),
            "url": d.get("url"), "desc": d.get("desc", ""),
            "about": d.get("about", ""), "wiki": d.get("wiki"), "github": d.get("github"),
            # Started on demand (a systemd socket, say), so a closed port means
            # asleep, not down. The check should use the app's own port, not the
            # socket's, or it wakes the app.
            "on_demand": bool(d.get("on_demand"))}


SERVICES = [_service(d) for d in config.get("services", [])]
SERVICE_HOST = config.get("service_host", "")   # for links when a service names no host
HOME = config.get("home")
# Tailnet logins that may use the briefing without the token. Tailscale Serve sets
# Tailscale-User-Login on requests from a user's devices and strips any copy a
# client sends. It is only believed on the Unix socket Serve forwards to
# (SERVE_SOCK): the TCP port is also reachable from containers with host-loopback
# access, and a request there could carry the header itself. See _owner().
TS_USERS = {u.strip().lower() for u in config.get("owners", [], env="DASH_TS_USERS") if u.strip()}
SERVE_SOCK = os.environ.get("DASH_SERVE_SOCK", "")


def _origin(url):
    u = urllib.parse.urlparse(url or "")
    return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else None


VANTAGE_ORIGIN = _origin(config.get("origin", "", env="DASH_ORIGIN"))   # Vantage itself, through Serve
DASHBOARD = config.get("dashboard") or {}
DASHBOARD_ORIGIN = _origin(DASHBOARD.get("url"))   # shows and clears the briefing

# A port that answers on the host, to tell which gateway address reaches it.
PROBE_PORT = config.get("gateway_probe_port") or (SERVICES[0]["port"] if SERVICES else None)


def resolve_host_gw():
    """Find the address that reaches the host's loopback-published ports:
    10.0.2.2 from a slirp4netns container, 127.0.0.1 when run on the host."""
    env = os.environ.get("HOST_GW", "").strip()
    candidates = ([env] if env and env != "auto" else []) + [
        "10.0.2.2", "host.containers.internal", "169.254.1.2", "127.0.0.1"]
    if PROBE_PORT is None:
        return candidates[0]      # nothing to check; nothing to reach either
    for cand in candidates:
        try:
            with socket.create_connection((cand, PROBE_PORT), timeout=2):
                print(f"host gateway: {cand}", flush=True)
                return cand
        except Exception:
            continue
    print("host gateway: none reachable yet, will retry in refresher", flush=True)
    return None


HOST_GW = resolve_host_gw()


def check_service(svc):
    t0 = time.monotonic()
    status, code = "down", 0
    if HOST_GW:
        try:
            conn = http.client.HTTPConnection(HOST_GW, svc["port"],
                                              timeout=CHECK_TIMEOUT)
            conn.request("GET", svc["path"], headers={"User-Agent": "vantage"})
            resp = conn.getresponse()
            code = resp.status
            resp.read(64)
            conn.close()
            ok = 200 <= code < 400 or code in svc["ok"]
            status = "up" if ok else "warn"
        except Exception:
            status = "idle" if svc["on_demand"] else "down"
    ms = round((time.monotonic() - t0) * 1000)
    host = svc["host"] or SERVICE_HOST
    url = svc["url"] or (f"https://{host}:{svc['public']}/" if host and svc["public"] else None)
    return {"name": svc["name"], "port": svc["port"], "status": status,
            "code": code, "ms": ms, "url": url, "desc": svc["desc"],
            "about": svc["about"], "wiki": svc["wiki"], "github": svc["github"]}


def read_host():
    out = {}
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            out["load"] = [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        out["load"] = [0, 0, 0]
    try:
        with open("/proc/uptime") as f:
            out["uptime"] = float(f.read().split()[0])
    except Exception:
        out["uptime"] = 0
    mem = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.strip().split()[0])  # kB
        out["mem_total"] = mem.get("MemTotal", 0)
        out["mem_avail"] = mem.get("MemAvailable", 0)
        out["swap_total"] = mem.get("SwapTotal", 0)
        out["swap_free"] = mem.get("SwapFree", 0)
    except Exception:
        pass
    try:
        with open("/proc/stat") as f:
            out["cores"] = sum(1 for ln in f
                               if ln.startswith("cpu") and ln[3].isdigit())
    except Exception:
        out["cores"] = 0
    try:
        with open("/proc/version") as f:
            out["kernel"] = f.read().split()[2]
    except Exception:
        out["kernel"] = "?"
    out["temp"] = read_temp()
    return out


def read_temp():
    """Highest CPU temperature from the host's hwmon sensors (how many mini PCs
    expose it) and thermal zones."""
    temps = []
    for path in (glob.glob(f"{HOST_SYS}/class/hwmon/*/temp*_input")
                 + glob.glob(f"{HOST_SYS}/class/thermal/thermal_zone*/temp")):
        try:
            with open(path) as f:
                v = int(f.read().strip()) / 1000
        except (OSError, ValueError):
            continue
        if 10 < v < 130:
            temps.append(v)
    return round(max(temps), 1) if temps else None


_net_prev = {"t": 0, "rx": 0, "tx": 0}


def read_net():
    """Physical-interface throughput (bytes/s) from host /proc/net/dev."""
    try:
        rx = tx = 0
        with open(f"{HOST_PROC}/net/dev") as f:
            for line in f.readlines()[2:]:
                iface, data = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo" or iface.startswith(
                        ("veth", "podman", "cni", "docker", "tailscale", "br-")):
                    continue
                c = data.split()
                rx += int(c[0]); tx += int(c[8])
        now = time.monotonic()
        dt = now - _net_prev["t"]
        rxr = txr = 0.0
        if _net_prev["t"] and dt > 0:
            rxr = max(0, (rx - _net_prev["rx"]) / dt)
            txr = max(0, (tx - _net_prev["tx"]) / dt)
        _net_prev.update(t=now, rx=rx, tx=tx)
        return {"rx": round(rxr), "tx": round(txr)}
    except Exception:
        return None


_cpu_prev = {"idle": 0, "total": 0}


def read_cpu_pct():
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        vals = [int(x) for x in parts]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        d_idle = idle - _cpu_prev["idle"]
        d_total = total - _cpu_prev["total"]
        _cpu_prev.update(idle=idle, total=total)
        if d_total <= 0:
            return 0.0
        return round(100.0 * (1 - d_idle / d_total), 1)
    except Exception:
        return 0.0


DISKS = config.get("disks", [{"name": "Root", "path": "/"}])


def read_disks():
    disks = []
    for d in DISKS:
        label, path = d["name"], d["path"]
        try:
            st = os.statvfs(path)
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            if total > 0:
                disks.append({"name": label, "total": total,
                              "used": total - free})
        except Exception:
            pass
    return disks


# ---------- uptime, disk trend, backup age ----------
STATE_DIR = config.STATE_DIR
BRIEFING_DIR = os.path.join(STATE_DIR, "briefing")   # written by a script on the host
# Lynis summaries and security alerts, written by a script on the host (README.md)
SECURITY_DIR = config.get("security_dir", os.path.join(STATE_DIR, "security"), env="DASH_SECURITY_DIR")
# Buttons on the Security page that ask the host to run a scan: [{"id", "label", "about"}]
SCANS_CFG = [{"id": s["id"], "label": s.get("label") or s["id"], "about": s.get("about", "")}
             for s in config.get("scans", [])]
BACKUP_PATH = config.get("backup_path", "", env="BACKUP_PATH")   # empty: no backup age
_ops = {"svc": {}, "disk": [], "disk_last": 0.0}
_ops_lock = threading.Lock()
_last_save = 0.0


def load_state():
    try:
        with open(os.path.join(STATE_DIR, "state.json")) as f:
            d = json.load(f)
        _ops["svc"] = d.get("svc", {})
        _ops["disk"] = d.get("disk", [])
        _ops["disk_last"] = d.get("disk_last", 0.0)
        print(f"ops state loaded: {len(_ops['svc'])} services, "
              f"{len(_ops['disk'])} disk samples", flush=True)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"state load error: {e}", flush=True)


def save_state():
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = os.path.join(STATE_DIR, "state.json.tmp")
        with open(tmp, "w") as f:
            json.dump(_ops, f)
        os.replace(tmp, os.path.join(STATE_DIR, "state.json"))
    except Exception as e:
        print(f"state save error: {e}", flush=True)


def track_ops(services, disks):
    """Accumulate per-service uptime and sample disk usage. Mutates the
    service dicts in place to add 'uptime' (%) and 'since' (epoch)."""
    global _last_save
    now = time.time()
    with _ops_lock:
        sv = _ops["svc"]
        for s in services:
            up = s["status"] != "down"
            rec = sv.get(s["name"])
            if rec is None:
                rec = {"up_sec": 0.0, "total_sec": 0.0, "since": now,
                       "up": up, "last_t": now}
                sv[s["name"]] = rec
            dt = now - rec["last_t"]
            if 0 < dt < 3600:                      # ignore restarts / clock jumps
                rec["total_sec"] += dt
                if rec["up"]:
                    rec["up_sec"] += dt
            if up != rec["up"]:
                rec["up"] = up
                rec["since"] = now
            rec["last_t"] = now
            s["uptime"] = (round(rec["up_sec"] / rec["total_sec"] * 100, 2)
                           if rec["total_sec"] > 0 else None)
            s["since"] = round(rec["since"])
        if now - _ops["disk_last"] >= 300:         # snapshot disk usage every 5 min
            _ops["disk"].append([round(now), {d["name"]: d["used"] for d in disks}])
            if len(_ops["disk"]) > 600:
                _ops["disk"] = _ops["disk"][-600:]
            _ops["disk_last"] = now
        if now - _last_save >= 60:
            _last_save = now
            save_state()


def disk_trend(disks):
    """Linear-fit each disk's usage history to bytes/day and days-to-full."""
    hist = _ops["disk"]
    for d in disks:
        d["perDay"] = None
        d["daysFull"] = None
        pts = [(t, u[d["name"]]) for t, u in hist if d["name"] in u]
        if len(pts) < 3:
            continue
        n = len(pts)
        t0 = pts[0][0]
        xs = [t - t0 for t, _ in pts]
        ys = [u for _, u in pts]
        mx = sum(xs) / n
        my = sum(ys) / n
        den = sum((x - mx) ** 2 for x in xs)
        if den <= 0:
            continue
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den  # bytes/s
        d["perDay"] = round(slope * 86400)
        if slope > 1:
            d["daysFull"] = round((d["total"] - d["used"]) / (slope * 86400), 1)


BACKUP_MAX_DEPTH = int(os.environ.get("BACKUP_MAX_DEPTH", "3"))


def read_backup_age():
    """Newest mtime under BACKUP_PATH, a few levels deep. A directory's mtime
    changes only when its own children do, and Borg writes into <repo>/data/N/,
    so the top level alone can look months old while backups run nightly."""
    newest = 0.0

    def walk(path, depth):
        nonlocal newest
        if depth > BACKUP_MAX_DEPTH:
            return
        try:
            with os.scandir(path) as it:
                for e in it:
                    try:
                        newest = max(newest, e.stat(follow_symlinks=False).st_mtime)
                        if e.is_dir(follow_symlinks=False):
                            walk(e.path, depth + 1)
                    except Exception:
                        pass
        except Exception:
            pass

    if not BACKUP_PATH:
        return None
    walk(BACKUP_PATH, 0)
    if newest > 0:
        return {"age": round(time.time() - newest), "mtime": round(newest)}
    return None


# ---------- peers (pushed stats from other devices) ----------
_peers = {}
_peers_lock = threading.Lock()
_peer_hist = {}   # name -> deque of samples for the charts


def store_peer(payload):
    """Keep a peer's latest reading and add it to the peer's history."""
    name = str(payload.get("name", ""))[:32]
    if not name:
        raise ValueError("no name")
    payload["received"] = time.time()
    with _peers_lock:
        _peers[name] = payload
        mt, ma = payload.get("mem_total", 0), payload.get("mem_avail", 0)
        hist = _peer_hist.setdefault(name, deque(maxlen=HISTORY_LEN))
        hist.append({"t": round(payload["received"]),
                     "cpu": payload.get("cpu", 0),
                     "mem": round((mt - ma) / mt * 100, 1) if mt else 0,
                     "temp": payload.get("temp"),
                     "battery": payload.get("battery")})


def _env_value(name):
    """An environment value without surrounding whitespace or quotes: env files
    are read literally, so KEY="value" would otherwise keep its quotes."""
    v = os.environ.get(name, "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    return v


def beszel_refresher(every=10):
    """Read the configured peer from Beszel's hub. Nothing is stored while
    Beszel has it down, so it goes stale as a silent agent would."""
    peer = config.get("peer") or {}
    b = peer.get("beszel")
    user, password = _env_value("DASH_BESZEL_USER"), _env_value("DASH_BESZEL_PASSWORD")
    if not (b and peer.get("name") and user and password):
        return
    token, total, last_error = None, 0, None
    while True:
        if not HOST_GW:             # not found yet; the refresher keeps looking
            time.sleep(every)
            continue
        step = "read"
        try:
            base = f"http://{HOST_GW}:{int(b.get('port', 8090))}"
            if not token:
                step = f"login as {user}"
                token = beszel.login(base, user, password)
                step = "read"
            payload, total = beszel.reading(base, peer["name"], b.get("system", peer["name"]), token, total)
            if payload:
                store_peer(payload)
            last_error = None
        except Exception as e:      # the hub down or restarting: try again next round
            what = repr(e)
            if isinstance(e, urllib.error.HTTPError):
                if e.code in (401, 403):
                    token = None
                try:
                    what = f"HTTP {e.code} {json.loads(e.read() or b'{}').get('message', '')}"
                except Exception:
                    what = f"HTTP {e.code}"
            if what != last_error:
                print(f"beszel peer: {step} failed: {what}", flush=True)
                last_error = what
        time.sleep(every)


def peer_snapshot():
    now = time.time()
    out = {}
    with _peers_lock:
        for name, p in _peers.items():
            q = dict(p)
            q["fresh"] = (now - p.get("received", 0)) < PEER_STALE
            out[name] = q
    return out


# ---------- world feeds (all keyless, cached here) ----------
UA = {"User-Agent": "vantage/1.0"}


def _get_json(url, timeout=10):
    with config.urlopen(
            urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return json.load(r)


def fetch_quakes():
    out = []
    try:
        feed = _get_json("https://earthquake.usgs.gov/earthquakes/feed/"
                         "v1.0/summary/2.5_day.geojson")
        for f in feed.get("features", [])[:40]:
            coords = f["geometry"]["coordinates"]
            lon, lat = coords[0], coords[1]
            depth = coords[2] if len(coords) > 2 else None
            p = f["properties"]
            out.append({"lat": lat, "lon": lon, "mag": p.get("mag"),
                        "place": p.get("place"), "time": p.get("time"),
                        "depth": depth, "url": p.get("url")})
    except Exception as e:
        print(f"quake feed error: {e}", flush=True)
    return out


def fetch_weather():
    if not HOME:
        return None
    try:
        cur = _get_json(
            f"https://api.open-meteo.com/v1/forecast?latitude={HOME['lat']}&longitude={HOME['lon']}"
            "&current=temperature_2m,weather_code&timezone=auto"
        ).get("current", {})
        return {"temp": cur.get("temperature_2m"), "code": cur.get("weather_code")}
    except Exception as e:
        print(f"weather error: {e}", flush=True)
        return None


def fetch_iss():
    try:
        d = _get_json("https://api.wheretheiss.at/v1/satellites/25544", timeout=8)
        return {"lat": d["latitude"], "lon": d["longitude"],
                "alt": d.get("altitude"), "vel": d.get("velocity")}
    except Exception:
        pass
    try:  # fallback: HTTP, no TLS
        d = _get_json("http://api.open-notify.org/iss-now.json", timeout=8)
        p = d["iss_position"]
        return {"lat": float(p["latitude"]), "lon": float(p["longitude"]),
                "alt": None, "vel": None}
    except Exception as e:
        print(f"iss error: {e}", flush=True)
        return None


def fetch_crypto():
    try:
        d = _get_json("https://api.coingecko.com/api/v3/simple/price?ids="
                      "bitcoin,ethereum&vs_currencies=usd&include_24hr_change=true")
        return {
            "btc": {"p": d["bitcoin"]["usd"], "c": d["bitcoin"].get("usd_24h_change")},
            "eth": {"p": d["ethereum"]["usd"], "c": d["ethereum"].get("usd_24h_change")},
        }
    except Exception as e:
        print(f"crypto error: {e}", flush=True)
        return None


def _iso_ts(iso):
    """'2026-09-24T08:45:00Z' -> epoch seconds; ValueError if it isn't ISO 8601."""
    return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def fetch_launch():
    """Next launch from Launch Library 2. Production, not lldev, which is not
    kept current; it allows 15 anonymous requests an hour and this makes 4.
    "upcoming" keeps a launch for a while after it flies, so take the first
    still ahead that has not succeeded or failed."""
    try:
        d = _get_json("https://ll.thespacedevs.com/2.3.0/launches/upcoming/"
                      "?limit=6&mode=list", timeout=12)
        now = time.time()
        for r in d.get("results", []):
            st = r.get("status") or {}
            abbrev = st.get("abbrev") if isinstance(st, dict) else None
            if abbrev in ("Success", "Failure", "Partial Failure"):
                continue
            try:
                net = _iso_ts(r.get("net") or "")
            except ValueError:
                continue
            if net < now:
                continue
            return {"name": r.get("name"), "net": r.get("net"), "status": abbrev,
                    "provider": (r.get("launch_service_provider") or {}).get("name")}
    except Exception as e:
        print(f"launch error: {e}", flush=True)
    return None


def fetch_kp():
    try:
        rows = _get_json(
            "https://services.swpc.noaa.gov/json/planetary_k_index_1m.json")
        if rows:
            last = rows[-1]
            kp = last.get("kp_index", last.get("estimated_kp"))
            return {"kp": round(float(kp), 1), "time": last.get("time_tag")}
    except Exception as e:
        print(f"kp error: {e}", flush=True)
    return None


def fetch_space():
    """Solar wind at L1 from NOAA SWPC: speed and the north-south component
    of the interplanetary field (Bz). Sustained southward Bz is what drives
    geomagnetic storms; Kp only reports them after the fact."""
    try:
        sp = _get_json("https://services.swpc.noaa.gov/products/summary/solar-wind-speed.json")
        mf = _get_json("https://services.swpc.noaa.gov/products/summary/solar-wind-mag-field.json")
        sp = sp[0] if isinstance(sp, list) and sp else sp or {}
        mf = mf[0] if isinstance(mf, list) and mf else mf or {}
        return {"speed": sp.get("proton_speed"), "bz": mf.get("bz_gsm"),
                "bt": mf.get("bt"), "time": sp.get("time_tag")}
    except Exception as e:
        print(f"space error: {e}", flush=True)
        return None


def fetch_air():
    """US AQI and PM2.5 at home from Open-Meteo's air-quality model (CAMS),
    keyless, hourly."""
    if not HOME:
        return None
    try:
        cur = _get_json("https://air-quality-api.open-meteo.com/v1/air-quality"
                        f"?latitude={HOME['lat']}&longitude={HOME['lon']}&current=us_aqi,pm2_5").get("current", {})
        return {"aqi": cur.get("us_aqi"), "pm25": cur.get("pm2_5"), "time": cur.get("time")}
    except Exception as e:
        print(f"air error: {e}", flush=True)
        return None


TS_KEY = os.environ.get("TAILSCALE_API_KEY", "").strip()


def fetch_tailnet():
    """All tailnet devices from the Tailscale API. Tailnet "-" is the key's own."""
    if not TS_KEY:
        return []
    try:
        req = urllib.request.Request(
            "https://api.tailscale.com/api/v2/tailnet/-/devices",
            headers={**UA, "Authorization": f"Bearer {TS_KEY}"})
        with config.urlopen(req, timeout=10) as r:
            data = json.load(r)
        out = []
        for d in data.get("devices", []):
            name = (d.get("name", "").split(".")[0]) or d.get("hostname", "?")
            out.append({"name": name, "os": d.get("os"),
                        "lastSeen": d.get("lastSeen"),
                        "update": d.get("updateAvailable", False)})
        return out
    except Exception as e:
        print(f"tailnet error: {e}", flush=True)
        return []


# ---------- map layers ------------------------------------------------------
# Everything here is keyless and public. Each layer is polled on its own
# interval, and most only while a browser is showing them (DEMAND_TTL), so an
# unwatched dashboard costs nothing.

_EONET_RAW = re.compile(r"\.(csv|json|xml|txt|ascat|kml|kmz)(\?|$)|irwin\.doi\.gov|scp\.byu\.edu", re.I)


def _eonet(category, limit=60):
    """NASA EONET open natural events, reduced to plottable points."""
    out = []
    feed = _get_json("https://eonet.gsfc.nasa.gov/api/v3/events"
                     f"?status=open&category={category}&limit={limit}", timeout=20)
    for e in feed.get("events", []):
        geo = (e.get("geometry") or [])
        if not geo:
            continue
        g = geo[-1]                       # last entry is the most recent position
        if g.get("type") != "Point":
            continue
        c = g.get("coordinates") or []
        if len(c) < 2:
            continue
        # e["link"] is EONET's own JSON API, not a page. Take the first source a
        # person can read, preferring NASA Earth Observatory write-ups; raw data
        # files (NATICE's CSV, BYU's ASCAT tracks) and IRWIN, which needs a
        # login, are dropped. The page offers a Worldview link regardless.
        srcs = [s.get("url") for s in e.get("sources") or [] if s.get("url")]
        srcs.sort(key=lambda u: 0 if ("earthobservatory" in u or "science.nasa.gov" in u) else 1)
        page = next((u for u in srcs if not _EONET_RAW.search(u)), None)
        out.append({"title": e.get("title"), "lon": c[0], "lat": c[1],
                    "date": g.get("date"), "url": page})
    return out


def fetch_cyclones():
    """Active named storms from the National Hurricane Center."""
    out = []
    d = _get_json("https://www.nhc.noaa.gov/CurrentStorms.json", timeout=15)
    for st in d.get("activeStorms", []):
        lat, lon = st.get("latitudeNumeric"), st.get("longitudeNumeric")
        if lat is None or lon is None:
            continue
        try:
            wind = int(st.get("intensity"))
        except (TypeError, ValueError):
            wind = None
        # NHC nests advisory links under per-product objects whose presence
        # varies by storm and basin: take the first that carries a url.
        url = None
        for key in ("publicAdvisory", "forecastAdvisory", "forecastDiscussion",
                    "forecastTrack", "windSpeedProbabilities"):
            prod = st.get(key)
            if isinstance(prod, dict) and prod.get("url"):
                url = prod["url"]
                break
        out.append({"name": st.get("name"), "cls": st.get("classification"),
                    "lat": lat, "lon": lon, "wind": wind,
                    "pressure": st.get("pressure"),
                    "dir": st.get("movementDir"), "speed": st.get("movementSpeed"),
                    "id": st.get("id"), "url": url or "https://www.nhc.noaa.gov/"})
    return out


GDACS_TYPES = {"EQ": "Earthquake", "TC": "Cyclone", "FL": "Flood",
               "VO": "Volcano", "WF": "Wildfire", "DR": "Drought"}


def fetch_incidents():
    """GDACS orange/red humanitarian alerts. Distinct from the USGS quake feed:
    this ranks by human impact, not magnitude."""
    out = []
    d = _get_json("https://www.gdacs.org/gdacsapi/api/events/geteventlist/"
                  "SEARCH?fromDate=&toDate=&alertlevel=Orange;Red", timeout=25)
    for f in d.get("features", []):
        g = f.get("geometry") or {}
        c = g.get("coordinates") or []
        if g.get("type") != "Point" or len(c) < 2:
            continue
        p = f.get("properties") or {}
        sev = (p.get("severitydata") or {}).get("severitytext")
        etype, eid = p.get("eventtype"), p.get("eventid")
        url = (f"https://www.gdacs.org/report.aspx?eventtype={etype}&eventid={eid}"
               if etype and eid else "https://www.gdacs.org/")
        out.append({"type": etype,
                    "kind": GDACS_TYPES.get(etype, etype),
                    "level": p.get("alertlevel"),
                    "name": p.get("eventname") or p.get("name"),
                    "country": p.get("country"), "sev": sev,
                    "lon": c[0], "lat": c[1], "from": p.get("fromdate"),
                    "id": eid, "url": url})
    return out


AURORA_MAX = 2600      # points sent to the browser, highest probability first


def fetch_aurora():
    """NOAA SWPC OVATION aurora forecast. The raw grid is 65k cells and about
    900 KB, nearly all of it zeros, so keep only the strongest cells."""
    d = _get_json("https://services.swpc.noaa.gov/json/ovation_aurora_latest.json",
                  timeout=25)
    cells = [c for c in d.get("coordinates", []) if len(c) >= 3 and c[2] >= 4]
    cells.sort(key=lambda c: -c[2])
    out = []
    for lon, lat, val in cells[:AURORA_MAX]:
        out.append([lon - 360 if lon > 180 else lon, lat, val])   # 0..360 -> -180..180
    return {"obs": d.get("Observation Time"), "fc": d.get("Forecast Time"),
            "peak": cells[0][2] if cells else 0, "cells": out}


AIRCRAFT_MAX = 1800


# OpenSky's anonymous quota is 400 credits a day per public IP, reset at
# midnight UTC, and a global query costs 4. It reports the balance on every
# reply, and the interval is graded on it, so a long session tapers rather than
# running dry: from a full day's credits, about 20 minutes at 30 s, 25 at 60 s,
# an hour at 150 s and two more at 10 minutes. The page moves each aircraft
# along its heading in between.
AIRCRAFT_STEPS = ((250, 30), (150, 60), (60, 150), (8, 600))   # (credits at least, seconds)
AIRCRAFT_FAST = AIRCRAFT_STEPS[0][1]
_opensky_left = None        # last x-rate-limit-remaining seen


def aircraft_interval():
    left = _opensky_left
    if left is None:
        return AIRCRAFT_FAST
    for floor, every in AIRCRAFT_STEPS:
        if left >= floor:
            return every
    return 3600             # all but spent: wait for the midnight UTC reset


def fetch_aircraft():
    """OpenSky, anonymous."""
    global _opensky_left
    req = urllib.request.Request("https://opensky-network.org/api/states/all",
                                 headers=UA)
    with config.urlopen(req, timeout=30) as r:
        left = r.headers.get("x-rate-limit-remaining")
        d = json.load(r)
    if left is not None and left.isdigit():
        _opensky_left = int(left)
    states = d.get("states") or []
    out = []
    for st in states:
        lon, lat = st[5], st[6]
        if lon is None or lat is None or st[8]:        # skip on-ground
            continue
        # three decimals (about 100 m), enough for the page's dead reckoning
        out.append([round(lon, 3), round(lat, 3),
                    round((st[13] or st[7] or 0) / 1000, 1),   # km
                    round(st[10] or 0),                         # heading
                    (st[1] or "").strip(),                      # callsign
                    st[0] or "",                                # icao24
                    round(st[9] or 0),                          # ground speed, m/s
                    st[3] or d.get("time"),                     # position time
                    flights.class_of(st[0])])                   # shape: H N R T L C, or ""
    # decimate after filtering, so the cap is the cap whatever the traffic
    if len(out) > AIRCRAFT_MAX:
        step = len(out) / AIRCRAFT_MAX
        out = [out[int(i * step)] for i in range(AIRCRAFT_MAX)]
    return {"t": d.get("time"), "n": len(states), "craft": out,
            "credits": _opensky_left, "every": aircraft_interval()}


HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.environ.get("STATIC_DIR") or (
    "/app/static" if os.path.isdir("/app/static") else os.path.join(HERE, "static"))
_countries = None


def countries():
    """ISO 3166-1 alpha-2 -> [lat, lon, name], from Google's DSPL canonical
    countries list, vendored as static/countries.json."""
    global _countries
    if _countries is None:
        with open(os.path.join(STATIC_DIR, "countries.json"), encoding="utf-8") as f:
            _countries = json.load(f)
    return _countries


# WHO and other sources name countries their own way; map those spellings to
# the ISO code the centroid table is keyed by.
COUNTRY_ALIAS = {
    "democratic republic of the congo": "CD", "dr congo": "CD", "drc": "CD",
    "republic of the congo": "CG", "congo": "CG",
    "united states of america": "US", "usa": "US",
    "united kingdom of great britain and northern ireland": "GB", "uk": "GB",
    "russian federation": "RU", "iran (islamic republic of)": "IR",
    "syrian arab republic": "SY", "viet nam": "VN", "lao people's democratic republic": "LA",
    "republic of korea": "KR", "democratic people's republic of korea": "KP",
    "united republic of tanzania": "TZ", "côte d'ivoire": "CI", "cote d'ivoire": "CI",
    "türkiye": "TR", "turkey": "TR", "bolivia (plurinational state of)": "BO",
    "venezuela (bolivarian republic of)": "VE", "republic of moldova": "MD",
    "occupied palestinian territory": "PS", "palestine": "PS", "kosovo": "XK",
    "cabo verde": "CV", "eswatini": "SZ", "czechia": "CZ", "myanmar": "MM",
    "timor-leste": "TL", "north macedonia": "MK",
}


def country_code(name):
    if not name:
        return None
    key = name.strip().lower()
    if key in COUNTRY_ALIAS:
        return COUNTRY_ALIAS[key]
    for code, (_lat, _lon, nm) in countries().items():
        if nm.lower() == key:
            return code
    return None


def fetch_outages():
    """Internet disruptions by country over the last 24 hours, from IODA
    (Georgia Tech): BGP, active probing and darknet signals combined. The
    `overall` score spans orders of magnitude, so the page sizes by its log."""
    now = int(time.time())
    d = _get_json("https://api.ioda.inetintel.cc.gatech.edu/v2/outages/summary"
                  f"?from={now - 86400}&until={now}&entityType=country", timeout=25)
    out = []
    for row in d.get("data", []):
        ent = row.get("entity") or {}
        code = ent.get("code")
        c = countries().get(code)
        if not c:
            continue
        score = (row.get("scores") or {}).get("overall") or 0
        out.append({"code": code, "name": ent.get("name") or c[2],
                    "lat": c[0], "lon": c[1], "score": score,
                    "events": row.get("event_cnt") or 0,
                    "url": f"https://ioda.inetintel.cc.gatech.edu/country/{code}"})
    out.sort(key=lambda r: -r["score"])
    return out


def fetch_outbreaks():
    """WHO Disease Outbreak News from the last 180 days, one marker per
    country (the newest report). Titles read "<disease> - <country>"."""
    url = ("https://www.who.int/api/news/diseaseoutbreaknews?sf_culture=en"
           "&$top=100&$orderby=PublicationDateAndTime%20desc")
    d = _get_json(url, timeout=30)
    cutoff = time.time() - 180 * 86400
    seen, out = set(), []
    for item in d.get("value", []):
        title = (item.get("Title") or item.get("OverrideTitle") or "").strip()
        when = item.get("PublicationDateAndTime") or ""
        try:
            ts = _iso_ts(when)
        except ValueError:
            continue
        if ts < cutoff or " - " not in title:
            continue
        disease, place = title.rsplit(" - ", 1)
        code = country_code(place)
        if not code or code in seen:
            continue
        seen.add(code)
        lat, lon, _ = countries()[code]
        out.append({"disease": disease.strip(), "country": place.strip(), "code": code,
                    "lat": lat, "lon": lon, "ts": int(ts),
                    "url": "https://www.who.int/emergencies/disease-outbreak-news/item/"
                           + (item.get("UrlName") or "")})
    return out


def fetch_alerts_ca():
    """Environment Canada's live public weather alerts (MSC GeoMet, keyless).
    One feature per forecast area; each comes back as its centroid plus an
    outline thinned to at most 48 points so the payload stays small."""
    d = _get_json("https://api.weather.gc.ca/collections/weather-alerts/items"
                  "?f=json&lang=en&limit=500", timeout=30)
    out = []
    for f in d.get("features", []):
        pr = f.get("properties") or {}
        g = f.get("geometry") or {}
        if g.get("type") == "Polygon":
            rings = [g["coordinates"][0]]
        elif g.get("type") == "MultiPolygon":
            rings = [poly[0] for poly in g["coordinates"]]
        else:
            continue
        ring = max(rings, key=len)
        if len(ring) < 3:
            continue
        step = max(1, len(ring) // 48)
        thin = [[round(p[0], 3), round(p[1], 3)] for p in ring[::step]]
        lon, lat = (sum(p[i] for p in ring) / len(ring) for i in (0, 1))
        out.append({"name": pr.get("alert_short_name_en") or pr.get("alert_name_en"),
                    "type": pr.get("alert_type"), "colour": pr.get("risk_colour_en"),
                    "area": pr.get("feature_name_en"), "prov": pr.get("province"),
                    "expires": pr.get("expiration_datetime"),
                    "lat": round(lat, 3), "lon": round(lon, 3), "ring": thin})
    return out


# CelesTrak asks clients not to refetch a group more than every two hours.
SAT_GROUPS = [("stations", "Space stations"), ("weather", "Weather"),
              ("resource", "Earth observation"), ("gnss", "Navigation")]


def fetch_sats():
    """Two-line elements for a few hundred satellites. The page propagates
    them itself (satellite.js), so positions move every second without the
    server polling anything."""
    out = []
    for group, label in SAT_GROUPS:
        with config.urlopen(urllib.request.Request(
                f"https://celestrak.org/NORAD/elements/gp.php?GROUP={group}&FORMAT=tle",
                headers=UA), timeout=25) as r:
            lines = [ln.rstrip() for ln in r.read().decode("utf-8", "replace").splitlines() if ln.strip()]
        for i in range(0, len(lines) - 2, 3):
            if lines[i + 1].startswith("1 ") and lines[i + 2].startswith("2 "):
                out.append([lines[i].strip(), lines[i + 1], lines[i + 2], label])
    return out


HEADLINE_FEEDS = [("BBC", "https://feeds.bbci.co.uk/news/world/rss.xml"),
                  ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"),
                  ("DW", "https://rss.dw.com/rdf/rss-en-world")]


def _rss_items(raw):
    """RSS 2.0 and RSS 1.0 (RDF, which DW still serves) item lists."""
    root = ET.fromstring(raw)
    items = root.findall("./channel/item")
    if not items:
        items = [e for e in root.iter() if e.tag.endswith("}item") or e.tag == "item"]
    out = []
    for it in items:
        def txt(name):
            for e in it:
                if e.tag == name or e.tag.endswith("}" + name):
                    return (e.text or "").strip()
            return ""
        when = txt("pubDate") or txt("date")
        ts = None
        try:
            ts = int(email.utils.parsedate_to_datetime(when).timestamp())
        except (TypeError, ValueError):
            try:
                ts = int(_iso_ts(when))
            except ValueError:
                pass
        out.append({"title": txt("title"), "url": txt("link"), "ts": ts})
    return out


def fetch_headlines():
    """World headlines from three public RSS feeds, newest first."""
    got = []
    for src, url in HEADLINE_FEEDS:
        try:
            with config.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
                for a in _rss_items(r.read())[:25]:
                    if a["title"] and a["url"]:
                        a["source"] = src
                        got.append(a)
        except Exception as e:
            print(f"headlines {src} error: {e}", flush=True)
    got.sort(key=lambda a: -(a["ts"] or 0))
    return got[:45]


# name: (fetch fn, interval seconds, only while a browser asks for it)
LAYER_JOBS = {
    "cyclones":  (fetch_cyclones,  900,   False),
    "incidents": (fetch_incidents, 1800,  False),
    "wildfires": (lambda: _eonet("wildfires", 120), 1800, True),
    "volcanoes": (lambda: _eonet("volcanoes", 60), 3600, True),
    "ice":       (lambda: _eonet("seaLakeIce", 60), 6 * 3600, True),
    "aurora":    (fetch_aurora,    900,   True),
    "aircraft":  (fetch_aircraft,  AIRCRAFT_FAST, True),   # paced by aircraft_interval()
    "outages":   (fetch_outages,   900,   True),
    "outbreaks": (fetch_outbreaks, 6 * 3600, True),
    "alerts":    (fetch_alerts_ca, 600,   True),
    "sats":      (fetch_sats,      6 * 3600, True),
}
DEMAND_TTL = 600        # an on-demand layer stops refreshing this long after the last ask
_layer_demand = {}
_layers = {}
_layers_t = {}
_layers_err = {}
# Set when a browser asks for a layer that has nothing yet, so the refresher
# fetches it now rather than on its next five-second pass.
_layers_wake = threading.Event()


def note_demand(names):
    now = time.monotonic()
    for n in names:
        if n in LAYER_JOBS:
            _layer_demand[n] = now
            if n not in _layers and n not in _layers_err:
                _layers_wake.set()


LAYER_RETRY = 90        # seconds before retrying a layer whose source failed


def layers_refresher():
    while True:
        now = time.monotonic()
        for name, (fn, interval, on_demand) in LAYER_JOBS.items():
            if on_demand and now - _layer_demand.get(name, -1e9) > DEMAND_TTL:
                continue
            if name == "aircraft":
                interval = aircraft_interval()
            if now - _layers_t.get(name, -1e9) < interval:
                continue
            try:
                _layers[name] = fn()
                _layers_err.pop(name, None)
                _layers_t[name] = now
            except Exception as e:
                # The last good data stays, so a source having a bad minute
                # leaves the map as it was; retry in LAYER_RETRY rather than a
                # whole interval, which for the slow layers would be hours.
                _layers_err[name] = str(e)
                print(f"layer {name} error: {e}", flush=True)
                _layers_t[name] = now - max(0, interval - LAYER_RETRY)
        _layers_wake.wait(5)
        _layers_wake.clear()


def get_layers(only=None):
    """`only` is the browser's enabled set; asking is what keeps an on-demand
    feed alive."""
    wanted = [n for n in (only or LAYER_JOBS.keys()) if n in LAYER_JOBS]
    note_demand(wanted)
    now = time.monotonic()
    out = {}
    for n in wanted:
        age = now - _layers_t[n] if n in _layers_t else None
        out[n] = {"data": _layers.get(n),
                  "age": round(age) if age is not None else None,
                  "error": _layers_err.get(n),
                  # not fetched yet: the page asks again in seconds, not 90
                  "pending": n not in _layers and n not in _layers_err}
    return out


_feeds = {"quakes": [], "headlines": [], "tailnet": []}
_feeds_t = {}


def feeds_refresher():
    while True:
        now = time.monotonic()
        for name, (fn, interval) in _FEED_JOBS.items():
            if now - _feeds_t.get(name, -1e9) >= interval:
                try:
                    _feeds[name] = fn()
                except Exception as e:
                    print(f"{name} refresh error: {e}", flush=True)
                _feeds_t[name] = now
        time.sleep(5)


# What /api/world may hand out without the token. _feeds also holds the attack
# surface and threat intel, which /api/recon and /api/threats keep behind it.
WORLD_KEYS = ("quakes", "weather", "iss", "crypto", "launch", "kp", "headlines", "space", "air")


def get_world():
    return {k: _feeds.get(k) for k in WORLD_KEYS}


# ---------- per-country news (Google News search RSS, keyless) ----------------
# Not GDELT DOC 2.0: it can answer 429 to every request from a network, the
# first of the day included and with a browser user agent, and then a country
# click shows no headlines at all.
#
# The globe's shapes come from world-atlas, whose ids are ISO 3166-1 numeric.
# Names below are CLDR display names from datasets/country-codes for exactly
# the territories world-atlas draws, with the few that read badly as a search
# ("US", "UK", "Congo - Kinshasa") replaced by the form headlines actually use.
ISO_NAME = {
    "004": 'Afghanistan', "008": 'Albania', "010": 'Antarctica',
    "012": 'Algeria', "016": 'American Samoa', "020": 'Andorra',
    "024": 'Angola', "028": 'Antigua and Barbuda', "031": 'Azerbaijan',
    "032": 'Argentina', "036": 'Australia', "040": 'Austria',
    "044": 'Bahamas', "048": 'Bahrain', "050": 'Bangladesh',
    "051": 'Armenia', "052": 'Barbados', "056": 'Belgium',
    "060": 'Bermuda', "064": 'Bhutan', "068": 'Bolivia',
    "070": 'Bosnia', "072": 'Botswana', "076": 'Brazil',
    "084": 'Belize', "086": 'British Indian Ocean Territory', "090": 'Solomon Islands',
    "092": 'British Virgin Islands', "096": 'Brunei', "100": 'Bulgaria',
    "104": 'Myanmar', "108": 'Burundi', "112": 'Belarus',
    "116": 'Cambodia', "120": 'Cameroon', "124": 'Canada',
    "132": 'Cape Verde', "136": 'Cayman Islands', "140": 'Central African Republic',
    "144": 'Sri Lanka', "148": 'Chad', "152": 'Chile',
    "156": 'China', "158": 'Taiwan', "170": 'Colombia',
    "174": 'Comoros', "178": 'Republic of the Congo', "180": 'DR Congo',
    "184": 'Cook Islands', "188": 'Costa Rica', "191": 'Croatia',
    "192": 'Cuba', "196": 'Cyprus', "203": 'Czechia',
    "204": 'Benin', "208": 'Denmark', "212": 'Dominica',
    "214": 'Dominican Republic', "218": 'Ecuador', "222": 'El Salvador',
    "226": 'Equatorial Guinea', "231": 'Ethiopia', "232": 'Eritrea',
    "233": 'Estonia', "234": 'Faroe Islands', "238": 'Falkland Islands',
    "239": 'South Georgia and South Sandwich Islands', "242": 'Fiji', "246": 'Finland',
    "250": 'France', "258": 'French Polynesia', "260": 'French Southern Territories',
    "262": 'Djibouti', "266": 'Gabon', "268": 'Georgia',
    "270": 'Gambia', "276": 'Germany', "288": 'Ghana',
    "292": 'Gibraltar', "296": 'Kiribati', "300": 'Greece',
    "304": 'Greenland', "308": 'Grenada', "316": 'Guam',
    "320": 'Guatemala', "324": 'Guinea', "328": 'Guyana',
    "332": 'Haiti', "334": 'Heard and McDonald Islands', "336": 'Vatican City',
    "340": 'Honduras', "344": 'Hong Kong', "348": 'Hungary',
    "352": 'Iceland', "356": 'India', "360": 'Indonesia',
    "364": 'Iran', "368": 'Iraq', "372": 'Ireland',
    "376": 'Israel', "380": 'Italy', "384": 'Ivory Coast',
    "388": 'Jamaica', "392": 'Japan', "398": 'Kazakhstan',
    "400": 'Jordan', "404": 'Kenya', "408": 'North Korea',
    "410": 'South Korea', "414": 'Kuwait', "417": 'Kyrgyzstan',
    "418": 'Laos', "422": 'Lebanon', "426": 'Lesotho',
    "428": 'Latvia', "430": 'Liberia', "434": 'Libya',
    "438": 'Liechtenstein', "440": 'Lithuania', "442": 'Luxembourg',
    "446": 'Macao', "450": 'Madagascar', "454": 'Malawi',
    "458": 'Malaysia', "462": 'Maldives', "466": 'Mali',
    "470": 'Malta', "478": 'Mauritania', "480": 'Mauritius',
    "484": 'Mexico', "492": 'Monaco', "496": 'Mongolia',
    "498": 'Moldova', "499": 'Montenegro', "500": 'Montserrat',
    "504": 'Morocco', "508": 'Mozambique', "512": 'Oman',
    "516": 'Namibia', "520": 'Nauru', "524": 'Nepal',
    "528": 'Netherlands', "531": 'Curaçao', "533": 'Aruba',
    "534": 'Sint Maarten', "540": 'New Caledonia', "548": 'Vanuatu',
    "554": 'New Zealand', "558": 'Nicaragua', "562": 'Niger',
    "566": 'Nigeria', "570": 'Niue', "574": 'Norfolk Island',
    "578": 'Norway', "580": 'Northern Mariana Islands', "583": 'Micronesia',
    "584": 'Marshall Islands', "585": 'Palau', "586": 'Pakistan',
    "591": 'Panama', "598": 'Papua New Guinea', "600": 'Paraguay',
    "604": 'Peru', "608": 'Philippines', "612": 'Pitcairn',
    "616": 'Poland', "620": 'Portugal', "624": 'Guinea-Bissau',
    "626": 'Timor-Leste', "630": 'Puerto Rico', "634": 'Qatar',
    "642": 'Romania', "643": 'Russia', "646": 'Rwanda',
    "652": 'Saint Barthélemy', "654": 'Saint Helena', "659": 'Saint Kitts and Nevis',
    "660": 'Anguilla', "662": 'Saint Lucia', "663": 'Saint Martin',
    "666": 'Saint Pierre and Miquelon', "670": 'Saint Vincent and Grenadines', "674": 'San Marino',
    "678": 'São Tomé and Príncipe', "682": 'Saudi Arabia', "686": 'Senegal',
    "690": 'Seychelles', "694": 'Sierra Leone', "702": 'Singapore',
    "703": 'Slovakia', "704": 'Vietnam', "705": 'Slovenia',
    "706": 'Somalia', "710": 'South Africa', "716": 'Zimbabwe',
    "724": 'Spain', "728": 'South Sudan', "729": 'Sudan',
    "732": 'Western Sahara', "740": 'Suriname', "748": 'Eswatini',
    "752": 'Sweden', "756": 'Switzerland', "760": 'Syria',
    "762": 'Tajikistan', "764": 'Thailand', "768": 'Togo',
    "776": 'Tonga', "780": 'Trinidad and Tobago', "784": 'United Arab Emirates',
    "788": 'Tunisia', "792": 'Türkiye', "795": 'Turkmenistan',
    "796": 'Turks and Caicos Islands', "798": 'Tuvalu', "800": 'Uganda',
    "804": 'Ukraine', "807": 'North Macedonia', "818": 'Egypt',
    "826": 'United Kingdom', "831": 'Guernsey', "832": 'Jersey',
    "833": 'Isle of Man', "834": 'Tanzania', "840": 'United States',
    "850": 'US Virgin Islands', "854": 'Burkina Faso', "858": 'Uruguay',
    "860": 'Uzbekistan', "862": 'Venezuela', "876": 'Wallis and Futuna',
    "882": 'Samoa', "887": 'Yemen', "894": 'Zambia',
}

# A bare name is a bad query when it is also a US state, a town, a person or
# part of a neighbour's name: "Jordan" alone returns West Jordan, Utah, and
# "Republic of the Congo" matches every story about the Democratic Republic of
# the Congo. Each of these was checked against the live feed.
# Capitals and demonyms rather than officials' names, since those change.
NEWS_QUERY = {
    "400": '"Jordan" (Amman OR Jordanian)',
    "268": '"Georgia" (Tbilisi OR Batumi OR "Georgian Dream" OR "Georgian government")',
    "148": '"Chad" (N\'Djamena OR Chadian)',
    "832": '"Jersey" ("St Helier" OR "Channel Islands" OR "States of Jersey")',
    "324": '"Guinea" (Conakry OR Guinean) -"Papua New Guinea" -"Equatorial Guinea" -"Guinea-Bissau"',
    "562": '"Niger" (Niamey OR Nigerien)',
    "422": '"Lebanon" (Beirut OR Lebanese)',
    "591": '"Panama" (Panamanian OR "Panama Canal")',
    "792": '("Turkey" OR "Türkiye") (Ankara OR Istanbul OR Turkish)',
    "729": '"Sudan" -"South Sudan"',
    "882": '"Samoa" -"American Samoa"',
    "212": '"Dominica" Roseau',
    "180": '"DR Congo" OR "Democratic Republic of the Congo" OR Kinshasa',
    "178": '"Congo-Brazzaville" OR "Pointe-Noire"',
    "384": '"Ivory Coast" OR "Côte d\'Ivoire" OR Abidjan',
    "826": '"United Kingdom" OR Britain OR UK',
    "484": '"Mexico" -"New Mexico"',
}

NEWS_TTL = 900          # a country's headlines stay good for fifteen minutes
NEWS_GAP = 1.0          # be a polite client: one request a second at most
NEWS_MAX = 12
NEWS_WINDOW = "2d"      # fresh first ...
NEWS_WIDE = "30d"       # ... then wider, for places with little daily coverage
_news = {}              # iso -> (fetched_at, articles)
_news_lock = threading.Lock()
_news_last = -1e9


def _news_query(iso):
    q = NEWS_QUERY.get(iso)
    return q if q else '"' + ISO_NAME[iso] + '"'


def _gnews(query, window):
    global _news_last
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": f"{query} when:{window}", "hl": "en-US", "gl": "US", "ceid": "US:en"})
    with _news_lock:
        wait = NEWS_GAP - (time.monotonic() - _news_last)
        if wait > 0:
            time.sleep(wait)
        _news_last = time.monotonic()
        with config.urlopen(
                urllib.request.Request(url, headers=UA), timeout=15) as r:
            raw = r.read()
    return ET.fromstring(raw).findall("./channel/item")


def _article(item):
    title = (item.findtext("title") or "").strip()
    src = item.find("source")
    source = (src.text or "").strip() if src is not None else ""
    # Google appends " - Outlet" to every title; the outlet is shown on its own
    if source and title.endswith(" - " + source):
        title = title[: -len(source) - 3].rstrip()
    domain = ""
    if src is not None and src.get("url"):
        domain = urllib.parse.urlparse(src.get("url")).netloc
        domain = domain[4:] if domain.startswith("www.") else domain
    seen = None
    try:
        seen = int(email.utils.parsedate_to_datetime(
            item.findtext("pubDate") or "").timestamp())
    except (TypeError, ValueError):
        pass
    return {"title": title, "url": item.findtext("link"),
            "domain": domain or source, "source": source, "lang": "en",
            "seen": seen}


def fetch_news(iso):
    query = _news_query(iso)
    items = _gnews(query, NEWS_WINDOW)
    if len(items) < 4:
        items = _gnews(query, NEWS_WIDE)
    out, seen_titles = [], set()
    for it in items:
        a = _article(it)
        key = re.sub(r"\W+", " ", a["title"].lower()).strip()
        if not a["title"] or key in seen_titles:
            continue      # the same wire story arrives from many outlets
        seen_titles.add(key)
        out.append(a)
    # Google ranks by relevance; a news panel wants newest first
    out.sort(key=lambda a: a["seen"] or 0, reverse=True)
    return out[:NEWS_MAX]


def get_news(iso):
    """Headlines for one ISO 3166-1 numeric country code. A stale cache beats
    an error page, so a failed refresh falls back to whatever was there."""
    iso = str(iso).strip().zfill(3)
    if iso not in ISO_NAME:
        return {"code": None, "articles": [],
                "error": "no news source for this territory"}
    now = time.monotonic()
    hit = _news.get(iso)
    if hit and now - hit[0] < NEWS_TTL:
        return {"code": iso, "name": ISO_NAME[iso], "articles": hit[1],
                "age": round(now - hit[0])}
    try:
        arts = fetch_news(iso)
    except Exception as e:
        if hit:
            return {"code": iso, "name": ISO_NAME[iso], "articles": hit[1],
                    "age": round(now - hit[0]), "error": str(e)}
        return {"code": iso, "name": ISO_NAME[iso], "articles": [], "error": str(e)}
    _news[iso] = (now, arts)
    return {"code": iso, "name": ISO_NAME[iso], "articles": arts, "age": 0}


_history = deque(maxlen=HISTORY_LEN)  # host samples for the charts

# A TLS certificate to count down, such as a web console's: the config's
# {"host", "port", "label"}. The host is the name the certificate is for; the
# connection goes to the host gateway, since the console listens on the host.
CERT = config.get("cert") or {}


def fetch_cert():
    """Days left on the configured TLS cert. Tailscale certs last 90 days and a
    renewal timer can fail quietly."""
    host = CERT.get("host")
    if not host:
        return {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((HOST_GW or "127.0.0.1", int(CERT.get("port", 443))), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        return {"host": host, "expires": exp,
                "days": round((exp - time.time()) / 86400, 1)}
    except Exception as e:
        return {"host": host, "error": str(e)[:90]}


def surface():
    """The attack surface: the slow external half (the recon feed) plus this
    host and the tailnet machines, read fresh from the host collector's file."""
    rec = dict(_feeds.get("recon") or {"external_pending": True})
    try:
        with open(recon.EXPOSURE) as f:
            exp = json.load(f)
    except (OSError, ValueError):
        exp = None
    host, machines, flags = recon.local_exposure(exp)
    return {**rec, "host": host, "machines": machines, "flags": (rec.get("flags") or []) + flags}


def posture():
    """One green, amber or red read of how healthy and how exposed everything is."""
    d = _cache.get("data") or {}
    items = []
    flag = lambda sev, text: items.append({"sev": sev, "text": text})
    down = [x["name"] for x in d.get("services", []) if x.get("status") == "down"]
    if down:
        flag("red", "services down: " + ", ".join(down))
    cert = d.get("cert") or {}
    if isinstance(cert.get("days"), (int, float)) and cert["days"] < 14:
        flag("red" if cert["days"] < 7 else "amber", f"TLS cert {cert['days']}d left")
    bk = d.get("backup")
    if bk and isinstance(bk.get("age"), (int, float)) and bk["age"] > 36 * 3600:
        flag("red", f"backup {round(bk['age']/3600)}h old")
    for dk in d.get("disks", []):
        pct = round(dk["used"] / dk["total"] * 100) if dk.get("total") else 0
        if pct >= 90:
            flag("red" if pct >= 95 else "amber", f"{dk['name']} {pct}% full")
    for f in surface().get("flags") or []:
        flag("amber", f)
    for f in (_feeds.get("threats") or {}).get("flags") or []:
        flag("red" if "ransomware" in f.lower() or "breach" in f.lower() else "amber", f)
    level = max((i["sev"] for i in items), key=("green", "amber", "red").index, default="green")
    if not items:
        flag("green", "all services up, certs valid, backups fresh, nothing exposed")
    return {"generated": round(time.time()), "level": level, "items": items,
            "active_alerts": len(store.active_alerts())}


def flight_watch():
    """Notify when an aircraft on the watch list is airborne, and clear the
    alert when it is not."""
    up = [a for a in flights.watch() if a]
    seen = {a.get("reg") or a["hex"] or "?" for a in up}
    for a in up:
        k = "flight:" + (a.get("reg") or a["hex"] or "?")
        name = a.get("reg") or a.get("callsign") or a["hex"]
        if store.set_alert(k, f"{name} airborne near {a.get('dist_nm', '?')}nm"):
            store.log_event("flight", k, "airborne")
            alerts.notify("Watched aircraft airborne", f"{name} ({a.get('type', '?')})", tags="airplane")
    for k in store.active_alerts():
        if k.startswith("flight:") and k[7:] not in seen and store.clear_alert(k):
            store.log_event("flight", k, "landed/out of range")


_FEED_JOBS = {  # name: (fn, interval seconds)
    "iss": (fetch_iss, 20),
    "quakes": (fetch_quakes, 600),
    "weather": (fetch_weather, 900),
    "crypto": (fetch_crypto, 120),
    "launch": (fetch_launch, 900),
    "kp": (fetch_kp, 1800),
    "headlines": (fetch_headlines, 600),
    "space": (fetch_space, 300),
    "air": (fetch_air, 1800),
    "acdb": (flights.load_acdb, 6 * 3600),   # aircraft types for the plane shapes; downloads weekly
    **({"tailnet": (fetch_tailnet, 90)} if TS_KEY else {}),
    "cert": (fetch_cert, 6 * 3600),
    "recon": (recon.attack_surface, 6 * 3600),
    "threats": (threatintel.gather, 3 * 3600),
    **({"flightwatch": (flight_watch, 90)} if flights.WATCH else {}),
}

_svc_hist = {}                          # per-service latency, for the node card
_svc_checked = {"t": 0.0, "list": []}   # the last round of service checks, and when


def build_status():
    global HOST_GW
    if HOST_GW is None:
        HOST_GW = resolve_host_gw()
    fresh = time.time() - _svc_checked["t"] >= SERVICE_EVERY
    if fresh:
        with ThreadPoolExecutor(max_workers=16) as ex:
            _svc_checked["list"] = list(ex.map(check_service, SERVICES))
        _svc_checked["t"] = time.time()
    services = _svc_checked["list"]
    host = read_host()
    host["cpu"] = read_cpu_pct()
    host["net"] = read_net()
    mem_pct = 0.0
    if host.get("mem_total"):
        mem_pct = round((host["mem_total"] - host.get("mem_avail", 0))
                        / host["mem_total"] * 100, 1)
    net = host.get("net") or {}
    _history.append({"t": round(time.time()), "cpu": host["cpu"], "mem": mem_pct,
                     "temp": host.get("temp"),
                     "rx": net.get("rx", 0), "tx": net.get("tx", 0)})
    disks = read_disks()
    track_ops(services, disks)
    disk_trend(disks)
    svc_map = None      # the services' results only when they were just checked
    if fresh:
        now = round(time.time())
        for s in services:
            _svc_hist.setdefault(s["name"], deque(maxlen=HISTORY_LEN)).append(
                {"t": now, "ms": s["ms"], "status": s["status"]})
        svc_map = {s["name"]: {"up": s["status"] in ("up", "warn", "idle"), "ms": s["ms"]} for s in services}
    store.record_sample(host.get("cpu"), mem_pct, host.get("temp"), net.get("rx", 0), net.get("tx", 0), svc_map)
    return {"generated": time.time(), "services": services, "checked": _svc_checked["t"],
            "host": host, "disks": disks, "peers": peer_snapshot(),
            "tailnet": _feeds.get("tailnet") or [], "backup": read_backup_age(),
            "cert": _feeds.get("cert") or {}}


_cache = {"data": None}
_last_prune = [0]


def refresher():
    while True:
        try:
            _cache["data"] = build_status()
            try:
                alerts.run(_cache["data"], surface(), _feeds.get("threats"))
            except Exception as e:
                print(f"alerts error: {e}", flush=True)
            if time.time() - _last_prune[0] > 6 * 3600:
                store.prune(); _last_prune[0] = time.time()
        except Exception as e:
            print(f"refresh error: {e}", flush=True)
        time.sleep(CACHE_TTL)


# Tailscale Serve passes bytes through untouched, and the status poll fires
# every 4 seconds per open screen, so text over 1 KB goes out gzipped.
COMPRESSIBLE = {"text/html", "application/json", "application/javascript", "text/css"}
GZIP_MIN = 1024
# Headers on everything but /static. No framing: a page that framed /briefing
# could steer a click onto Clear.
PRIVATE = {"Cache-Control": "no-store", "X-Frame-Options": "DENY",
           "Content-Security-Policy": "frame-ancestors 'none'"}
STATIC_TYPES = {".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml",
                ".woff2": "font/woff2"}

# Compressed copies of files on disk, keyed by path and mtime, so each is
# compressed once per change rather than once per load.
_gz_files = {}


def _gz_file(path, raw):
    mtime = os.stat(path).st_mtime_ns
    hit = _gz_files.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    body = gzip.compress(raw, 6)
    _gz_files[path] = (mtime, body)
    return body


# What the page needs to know about this site: names, links and places from
# the config, never a secret. Written into index.html as it is served.
PAGE_CONFIG = json.dumps({
    "host": config.get("host") or {}, "peer": config.get("peer"),
    "dashboard": DASHBOARD or None, "history_link": config.get("history_link"),
    "home": HOME, "cities": config.get("cities"),
    "disks": [d["name"] for d in DISKS], "cert_label": CERT.get("label"),
    "constellation": config.get("constellation") is True,
}).replace("</", "<\\/").encode()

# GET routes that need the token or the owner's login (/api/briefing and
# /api/osint check for themselves)
TOKEN_GETS = ("/api/posture", "/api/events", "/api/security", "/api/trends", "/api/recon", "/api/threats")

_osint_cache = {}


def _osint_memo(key, ttl, fn):
    now = time.time()
    hit = _osint_cache.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _osint_cache[key] = (now, val)
    return val


class Handler(BaseHTTPRequestHandler):
    via_serve = False       # True on the Tailscale Serve socket

    def log_message(self, *a):
        pass

    def _accepts_gzip(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "").lower()

    def _authed(self, dashboard=False):
        """The dashboard token, or the owner (see _owner), so the owner's
        devices never have to type the token."""
        # bytes: compare_digest raises on a str with non-ASCII in it
        return (hmac.compare_digest((self.headers.get("X-Dash-Token") or "").encode(), TOKEN.encode())
                or self._owner(dashboard))

    def _owner(self, dashboard=False):
        """The owner, recognised by the tailnet login Tailscale Serve sets. That
        header rides on every request from the owner's devices, including ones
        another website makes the browser send, so it only counts for Vantage's
        own pages, a typed address or a non-browser client; with dashboard=True
        (the briefing widget) also the dashboard, whose cross-port requests carry
        its Origin. Browsers set Sec-Fetch-Site and Origin themselves; a page
        cannot forge them."""
        if not self.via_serve:
            return False
        if not TS_USERS or self.headers.get("Tailscale-User-Login", "").strip().lower() not in TS_USERS:
            return False
        site, origin = self.headers.get("Sec-Fetch-Site"), self.headers.get("Origin")
        ok_origins = {None, VANTAGE_ORIGIN} | ({DASHBOARD_ORIGIN} if dashboard else set())
        if site in (None, "same-origin", "none"):
            # A browser too old for Sec-Fetch-Site still sends Origin on a
            # cross-origin POST, so another site's form is refused here too.
            return origin in ok_origins
        return dashboard and bool(DASHBOARD_ORIGIN) and site == "same-site" and origin == DASHBOARD_ORIGIN

    def _briefing_get(self):
        if not self._authed(dashboard=True):
            return self._send(403, b'{"error":"forbidden"}')
        folder = BRIEFING_DIR
        url = urllib.parse.urlparse(self.path)
        try:
            if url.path == "/api/briefing/history":
                return self._send(200, json.dumps(briefing.history(folder)).encode())
            if url.path == "/api/briefing/day":
                d = briefing.day(folder, (urllib.parse.parse_qs(url.query).get("d") or [""])[0])
                return self._send(200 if d else 404, json.dumps(d or {"error": "no such day"}).encode())
            # the latest, with what was cleared left out
            report = briefing.with_keys(briefing.latest(folder), briefing.done(), hide_done=True)
            return self._send(200, json.dumps(report).encode())
        except FileNotFoundError:
            return self._send(404, b'{"error":"no briefing yet"}')

    # Scans the Security page can ask for, from the config's "scans". Asking
    # writes SECURITY_DIR/requests/<id>; something on the host (a systemd path
    # unit, say) watches for that file and runs the scan.
    SCANS = {s["id"] for s in SCANS_CFG}
    SCAN_GAP = 600          # seconds before the same scan can be asked for again
    _scan_asked = {}

    def _security_run(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 4096)) if length else b""
        if not self._authed():
            return self._send(403, b'{"error":"forbidden"}')
        try:
            scan = str(json.loads(raw or b"{}").get("scan", ""))
        except (ValueError, AttributeError):
            return self._send(400, b'{"error":"bad json"}')
        if scan not in self.SCANS:
            return self._send(400, b'{"error":"unknown scan"}')
        now = time.time()
        if now - Handler._scan_asked.get(scan, 0) < self.SCAN_GAP:
            return self._send(429, json.dumps({"error": f"{scan} was started less than 10 minutes ago"}).encode())
        folder = os.path.join(SECURITY_DIR, "requests")
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, scan), "w") as f:
                f.write(str(round(now)))
        except OSError as e:
            return self._send(500, json.dumps({"error": f"could not ask for the scan: {e}"}).encode())
        Handler._scan_asked[scan] = now
        self._send(202, json.dumps({"ok": True, "scan": scan}).encode())

    def _briefing_post(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 65536)) if length else b""
        if not self._authed(dashboard=True):
            return self._send(403, b'{"error":"forbidden"}')
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self._send(400, b'{"error":"bad json"}')
        if not isinstance(body, dict):
            return self._send(400, b'{"error":"bad json"}')
        keys = body.get("keys") or []
        if body.get("all"):
            try:
                keys = briefing.keys_of(briefing.latest(BRIEFING_DIR))
            except FileNotFoundError:
                keys = []
        marks = briefing.mark([str(k) for k in keys][:200], undo=self.path.startswith("/api/briefing/undo"))
        return self._send(200, json.dumps({"ok": True, "done": len(marks)}).encode())

    def do_OPTIONS(self):
        # CORS preflight for the dashboard's briefing widget only
        if (DASHBOARD_ORIGIN and self.path.startswith("/api/briefing")
                and self.headers.get("Origin") == DASHBOARD_ORIGIN):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "GET, POST")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
            self.end_headers()
        else:
            self._send(404, b"not found", "text/plain")

    def _osint(self, method):
        if not self._authed():
            return self._send(403, b'{"error":"forbidden"}')
        u = urllib.parse.urlparse(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query)
        one = lambda k, d=None: (q.get(k) or [d])[0]
        try:
            if method == "POST" and path == "/api/osint/exif":
                n = int(self.headers.get("Content-Length", 0))
                if n > 30_000_000:
                    return self._send(413, b'{"error":"image too large"}')
                data = self.rfile.read(n)
                return self._send(200, json.dumps(imagery.exif(data)).encode())
            if method == "GET" and path == "/api/osint/flights":
                lat, lon = one("lat"), one("lon")
                nm = int(one("nm", "0")) or None
                key = f"fl:{lat}:{lon}:{nm}"
                board = _osint_memo(key, 20, lambda: (
                    flights.overhead(float(lat), float(lon), nm) if lat and lon else flights.board()))
                return self._send(200, json.dumps(board).encode())
            if method == "GET" and path == "/api/osint/flight":
                qq = one("q", "").strip()
                if not qq:
                    return self._send(400, b'{"error":"q required"}')
                return self._send(200, json.dumps(
                    _osint_memo("find:" + qq, 15, lambda: flights.find(qq))).encode())
            if method == "GET" and path == "/api/osint/sun":
                lat, lon = one("lat"), one("lon")
                if not (lat and lon):
                    return self._send(400, b'{"error":"lat and lon required"}')
                return self._send(200, json.dumps(
                    imagery.sun(float(lat), float(lon), one("t"))).encode())
            if method == "GET" and path == "/api/osint/place":
                lat, lon = one("lat"), one("lon")
                if not (lat and lon):
                    return self._send(400, b'{"error":"lat and lon required"}')
                return self._send(200, json.dumps(
                    _osint_memo(f"place:{lat}:{lon}", 3600,
                                lambda: imagery.place(float(lat), float(lon)))).encode())
        except (ValueError, TypeError) as e:
            return self._send(400, json.dumps({"error": str(e)[:120]}).encode())
        return self._send(404, b'{"error":"no such osint call"}')

    def _send(self, code, body, ctype="application/json", gz_body=None, headers=PRIVATE):
        compressible = ctype.split(";")[0].strip() in COMPRESSIBLE
        encoded = False
        if compressible and len(body) >= GZIP_MIN and self._accepts_gzip():
            # level 5: most of level 9's ratio at a fraction of the CPU
            body = gz_body if gz_body is not None else gzip.compress(body, 5)
            encoded = True
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in headers.items():
                self.send_header(k, v)
            if (DASHBOARD_ORIGIN and self.path.startswith("/api/briefing")
                    and self.headers.get("Origin") == DASHBOARD_ORIGIN):
                self.send_header("Access-Control-Allow-Origin", DASHBOARD_ORIGIN)
                self.send_header("Vary", "Origin")
            if encoded:
                self.send_header("Content-Encoding", "gzip")
            if compressible:
                self.send_header("Vary", "Accept-Encoding")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path.startswith(TOKEN_GETS) and not self._authed():
            return self._send(403, b'{"error":"forbidden"}')
        if self.path.startswith("/api/whoami"):
            # the page asks once, and skips the token prompt for the owner
            self._send(200, json.dumps({"owner": self._owner()}).encode())
        elif self.path.startswith("/api/status"):
            data = _cache["data"]
            if data is None:
                self._send(503, b'{"booting":true}')
            else:
                data = dict(data, peers=peer_snapshot())   # freshness is per request
                self._send(200, json.dumps(data).encode())
        elif self.path.startswith("/api/osint/"):
            self._osint("GET")
        elif self.path.startswith("/api/posture"):
            self._send(200, json.dumps(posture()).encode())
        elif self.path.startswith("/api/events"):
            self._send(200, json.dumps({"events": store.recent_events(120),
                                        "active": store.active_alerts()}).encode())
        elif self.path.startswith("/api/briefing"):
            return self._briefing_get()
        elif self.path.startswith("/api/security"):
            self._send(200, json.dumps({**security.report(SECURITY_DIR), "scans": SCANS_CFG}).encode())
        elif urllib.parse.urlparse(self.path).path in ("/briefing", "/security"):
            # one page for both, holding no data; it opens on security at /security
            try:
                with open(os.path.join(HERE, "briefing.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, b"not found", "text/plain")
        elif self.path.startswith("/api/trends"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                hrs = max(1, min(720, int((q.get("h") or ["24"])[0])))
            except ValueError:
                return self._send(400, b'{"error":"h must be a number of hours"}')
            self._send(200, json.dumps(store.samples_since(hrs * 3600)).encode())
        elif self.path.startswith("/api/recon"):
            self._send(200, json.dumps(surface()).encode())
        elif self.path.startswith("/api/threats"):
            self._send(200, json.dumps(_feeds.get("threats") or {"booting": True}).encode())
        elif self.path.startswith("/api/world"):
            self._send(200, json.dumps(get_world()).encode())
        elif self.path.startswith("/api/news"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            iso = (q.get("iso") or [""])[0]
            self._send(200, json.dumps(get_news(iso)).encode())
        elif self.path.startswith("/api/layers"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            only = [n for v in q.get("only", []) for n in v.split(",") if n]
            self._send(200, json.dumps(get_layers(only or None)).encode())
        elif self.path.startswith("/static/"):
            # Vendored map data and the artwork, plus any public files of your
            # own put beside them. cables.json is cables.py's copy in STATE_DIR.
            name = os.path.basename(urllib.parse.urlparse(self.path).path)
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name or ""):
                return self._send(400, b"bad name", "text/plain")
            path = cables.PATH if name == "cables.json" else os.path.join(STATIC_DIR, name)
            ctype = STATIC_TYPES.get(os.path.splitext(name)[1], "application/octet-stream")
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except (FileNotFoundError, IsADirectoryError):
                return self._send(404, b"not found", "text/plain")
            # changes at most once per restart, so the browser keeps it for a day
            headers = {"Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff"}
            if ctype == "image/svg+xml":
                # opened directly, an SVG could run script on this origin
                headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"
            if ctype == "image/png":
                # icons may be used cross-origin, as a dashboard's favicon or a PWA icon
                headers["Access-Control-Allow-Origin"] = "*"
                headers["Cross-Origin-Resource-Policy"] = "cross-origin"
            gz = _gz_file(path, body) if ctype in COMPRESSIBLE and self._accepts_gzip() else None
            self._send(200, body, ctype, gz, headers)
        elif self.path.startswith("/api/history"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            peer, svc = (q.get("peer") or [None])[0], (q.get("service") or [None])[0]
            if peer:
                with _peers_lock:
                    out = list(_peer_hist.get(peer, []))
            elif svc:
                out = list(_svc_hist.get(svc, []))
            else:
                out = list(_history)
            self._send(200, json.dumps(out).encode())
        elif self.path in ("/", "/index.html"):
            path = os.path.join(HERE, "index.html")
            try:
                with open(path, "rb") as f:
                    raw = f.read().replace(b"/*VANTAGE_CONFIG*/{}", PAGE_CONFIG, 1)
                self._send(200, raw, "text/html; charset=utf-8",
                           gz_body=_gz_file(path, raw) if self._accepts_gzip() else None)
            except FileNotFoundError:
                self._send(500, b"index.html missing", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path.startswith(("/api/briefing/done", "/api/briefing/undo")):
            return self._briefing_post()
        if self.path.startswith("/api/osint/"):
            return self._osint("POST")
        if self.path.startswith("/api/security/run"):
            return self._security_run()
        if not self.path.startswith("/api/push"):
            self._send(404, b"not found", "text/plain")
            return
        if not self._authed():
            self._send(403, b"forbidden", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            store_peer(json.loads(self.rfile.read(length)))
            self._send(200, b'{"ok":true}')
        except Exception:
            self._send(400, b"bad payload", "text/plain")


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("DASH_TOKEN is required (set it in the unit's "
                         "EnvironmentFile); refusing to start with no push auth")
    # As PID 1 in a container Python would ignore SIGTERM; stop cleanly instead
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    read_cpu_pct()  # prime the delta
    load_state()
    threading.Thread(target=refresher, daemon=True).start()
    threading.Thread(target=beszel_refresher, daemon=True).start()
    threading.Thread(target=feeds_refresher, daemon=True).start()
    threading.Thread(target=layers_refresher, daemon=True).start()
    threading.Thread(target=cables.refresh, daemon=True).start()
    if SERVE_SOCK:
        # The listener Tailscale Serve forwards to, in Vantage's state folder. A
        # container that mounts that folder (even read-only) can connect to it and
        # send the login header, so keep the state folder out of other containers.
        class ServeHandler(Handler):
            via_serve = True

            def address_string(self):
                return "serve"

        class ServeServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        try:
            os.unlink(SERVE_SOCK)
        except FileNotFoundError:
            pass
        serve = ServeServer(SERVE_SOCK, ServeHandler)
        os.chmod(SERVE_SOCK, 0o600)   # only the owner; tailscaled connects as root
        threading.Thread(target=serve.serve_forever, daemon=True).start()
        print(f"vantage on {SERVE_SOCK} for Tailscale Serve", flush=True)
    print(f"vantage on {BIND}:{PORT}", flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
