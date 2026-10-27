#!/usr/bin/env python3
"""Small SQLite store for Vantage, so history and alert state survive a restart.

Uses the stdlib sqlite3 module and the /state mount.
Three tables:
  samples   one row per status refresh: cpu, mem, temp, and per-service up/latency
  events    service/host state changes (up->down, cert low, backup stale): the log
  alerts    which alerts are currently firing, so we notify on change, not every tick

Everything is best-effort: if the database can't be opened the dashboard still
runs on its in-memory caches, it just loses history across restarts.
"""
import json
import os
import sqlite3
import threading
import time

import config

DB_PATH = os.path.join(config.STATE_DIR, "vantage.db")
RETAIN_DAYS = int(config.get("retain_days", 30, env="DASH_RETAIN_DAYS"))
_lock = threading.Lock()
_conn = None


def _db():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.executescript("""
            CREATE TABLE IF NOT EXISTS samples(
                t INTEGER PRIMARY KEY, cpu REAL, mem REAL, temp REAL,
                rx INTEGER, tx INTEGER, services TEXT);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER, kind TEXT,
                subject TEXT, detail TEXT);
            CREATE INDEX IF NOT EXISTS events_t ON events(t);
            CREATE TABLE IF NOT EXISTS alerts(
                key TEXT PRIMARY KEY, since INTEGER, detail TEXT);
            CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
        """)
    return _conn


def ok():
    try:
        _db()
        return True
    except Exception as e:
        print(f"store: db unavailable: {e}", flush=True)
        return False


def record_sample(host_cpu, mem, temp, rx, tx, services):
    """One row per refresh. `services` is a {name: {"up":bool,"ms":int}} dict, or None
    when the services weren't checked this time (stored as NULL)."""
    try:
        with _lock:
            c = _db()
            c.execute("INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?)",
                      (int(time.time()), host_cpu, mem, temp, rx, tx, None if services is None else json.dumps(services)))
            c.commit()
    except Exception:
        pass


def log_event(kind, subject, detail=""):
    try:
        with _lock:
            c = _db()
            c.execute("INSERT INTO events(t,kind,subject,detail) VALUES (?,?,?,?)",
                      (int(time.time()), kind, subject, detail))
            c.commit()
    except Exception:
        pass


def recent_events(limit=100):
    try:
        with _lock:
            rows = _db().execute(
                "SELECT t,kind,subject,detail FROM events ORDER BY t DESC LIMIT ?",
                (limit,)).fetchall()
        return [{"t": r[0], "kind": r[1], "subject": r[2], "detail": r[3]} for r in rows]
    except Exception:
        return []


def samples_since(seconds):
    try:
        cut = int(time.time()) - seconds
        with _lock:
            rows = _db().execute(
                "SELECT t,cpu,mem,temp,rx,tx FROM samples WHERE t>=? ORDER BY t", (cut,)).fetchall()
        return [{"t": r[0], "cpu": r[1], "mem": r[2], "temp": r[3], "rx": r[4], "tx": r[5]} for r in rows]
    except Exception:
        return []


def active_alerts():
    try:
        with _lock:
            rows = _db().execute("SELECT key,since,detail FROM alerts ORDER BY since").fetchall()
        return {r[0]: {"since": r[1], "detail": r[2]} for r in rows}
    except Exception:
        return {}


def set_alert(key, detail):
    """Mark an alert firing. Returns True only the first time (so callers notify once)."""
    try:
        with _lock:
            c = _db()
            row = c.execute("SELECT key FROM alerts WHERE key=?", (key,)).fetchone()
            if row:
                return False
            c.execute("INSERT INTO alerts(key,since,detail) VALUES (?,?,?)",
                      (key, int(time.time()), detail))
            c.commit()
            return True
    except Exception:
        return False


def clear_alert(key):
    """Clear an alert. Returns True only if it was firing (so callers notify recovery)."""
    try:
        with _lock:
            c = _db()
            row = c.execute("SELECT key FROM alerts WHERE key=?", (key,)).fetchone()
            if not row:
                return False
            c.execute("DELETE FROM alerts WHERE key=?", (key,))
            c.commit()
            return True
    except Exception:
        return False


def uptime_pct(service, seconds):
    """Share of samples in the window where a service was up, from the samples log."""
    try:
        cut = int(time.time()) - seconds
        with _lock:
            rows = _db().execute("SELECT services FROM samples WHERE t>=?", (cut,)).fetchall()
        up = tot = 0
        for (sj,) in rows:
            s = json.loads(sj or "{}").get(service)
            if s is None:
                continue
            tot += 1
            up += 1 if s.get("up") else 0
        return round(up / tot * 100, 2) if tot else None
    except Exception:
        return None


def get_json(key, default=None):
    try:
        with _lock:
            row = _db().execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default
    except Exception:
        return default


def set_json(key, value):
    try:
        with _lock:
            c = _db()
            c.execute("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))
            c.commit()
    except Exception:
        pass


def prune():
    try:
        cut = int(time.time()) - RETAIN_DAYS * 86400
        with _lock:
            c = _db()
            c.execute("DELETE FROM samples WHERE t<?", (cut,))
            c.execute("DELETE FROM events WHERE t<?", (cut,))
            c.commit()
    except Exception:
        pass


if __name__ == "__main__":
    import tempfile
    os.environ["STATE_DIR"] = tempfile.mkdtemp()
    globals()["DB_PATH"] = os.path.join(os.environ["STATE_DIR"], "vantage.db")
    assert ok()
    record_sample(12.0, 44.0, 51.0, 100, 50, {"Wiki": {"up": True, "ms": 20}, "Media": {"up": False, "ms": 0}})
    time.sleep(1)
    record_sample(14.0, 45.0, 52.0, 200, 90, {"Wiki": {"up": True, "ms": 25}, "Media": {"up": True, "ms": 30}})
    assert len(samples_since(3600)) == 2, "two samples"
    assert set_alert("svc:Media", "down") is True, "first set fires"
    assert set_alert("svc:Media", "down") is False, "second set is quiet"
    assert "svc:Media" in active_alerts()
    assert clear_alert("svc:Media") is True, "clear fires once"
    assert clear_alert("svc:Media") is False, "second clear quiet"
    log_event("recovery", "Media", "back up")
    assert recent_events()[0]["subject"] == "Media"
    assert uptime_pct("Wiki", 3600) == 100.0
    assert uptime_pct("Media", 3600) == 50.0
    set_json("base:x", ["a", "b"]); assert get_json("base:x") == ["a", "b"]
    assert get_json("nope", []) == []
    print("store.py self-check passed")
