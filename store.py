#!/usr/bin/env python3
"""SQLite store for Vantage, so history and alert state survive a restart.

  samples   one row per status refresh: cpu, mem, temp, and per-service up/latency
  events    service and host state changes: the log
  alerts    which alerts are firing, so a notification goes out on change, not every tick
  kv        small JSON values other modules keep (cleared briefing items, CT baselines)

Everything is best-effort: if the database can't be opened the dashboard still
runs on its in-memory caches and only loses history across restarts.
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


def _run(sql, args=(), default=None):
    """One statement under the lock: the rows of a query, the row count of a
    write, or `default` if the database is unavailable."""
    try:
        with _lock:
            c = _db()
            cur = c.execute(sql, args)
            if cur.description is not None:
                return cur.fetchall()
            c.commit()
            return cur.rowcount
    except Exception:
        return default


def record_sample(host_cpu, mem, temp, rx, tx, services):
    """`services` is {name: {"up": bool, "ms": int}}, or None when the services
    weren't checked this time (stored as NULL)."""
    _run("INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?)",
         (int(time.time()), host_cpu, mem, temp, rx, tx, None if services is None else json.dumps(services)))


def log_event(kind, subject, detail=""):
    _run("INSERT INTO events(t,kind,subject,detail) VALUES (?,?,?,?)", (int(time.time()), kind, subject, detail))


def recent_events(limit=100):
    rows = _run("SELECT t,kind,subject,detail FROM events ORDER BY t DESC LIMIT ?", (limit,), [])
    return [{"t": r[0], "kind": r[1], "subject": r[2], "detail": r[3]} for r in rows]


def samples_since(seconds):
    rows = _run("SELECT t,cpu,mem,temp,rx,tx FROM samples WHERE t>=? ORDER BY t", (int(time.time()) - seconds,), [])
    return [{"t": r[0], "cpu": r[1], "mem": r[2], "temp": r[3], "rx": r[4], "tx": r[5]} for r in rows]


def active_alerts():
    rows = _run("SELECT key,since,detail FROM alerts ORDER BY since", default=[])
    return {r[0]: {"since": r[1], "detail": r[2]} for r in rows}


def set_alert(key, detail):
    """Mark an alert firing. True only the first time, so callers notify once."""
    return _run("INSERT OR IGNORE INTO alerts(key,since,detail) VALUES (?,?,?)",
                (key, int(time.time()), detail), 0) == 1


def clear_alert(key):
    """True only if it was firing, so callers notify the recovery once."""
    return _run("DELETE FROM alerts WHERE key=?", (key,), 0) == 1


def get_json(key, default=None):
    rows = _run("SELECT v FROM kv WHERE k=?", (key,))
    try:
        return json.loads(rows[0][0]) if rows else default
    except ValueError:
        return default


def set_json(key, value):
    _run("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))


def prune():
    cut = int(time.time()) - RETAIN_DAYS * 86400
    _run("DELETE FROM samples WHERE t<?", (cut,))
    _run("DELETE FROM events WHERE t<?", (cut,))


if __name__ == "__main__":
    import tempfile
    DB_PATH = os.path.join(tempfile.mkdtemp(), "vantage.db")
    record_sample(12.0, 44.0, 51.0, 100, 50, {"Wiki": {"up": True, "ms": 20}, "Media": {"up": False, "ms": 0}})
    time.sleep(1)
    record_sample(14.0, 45.0, 52.0, 200, 90, None)
    assert len(samples_since(3600)) == 2, "two samples"
    assert set_alert("svc:Media", "down") is True, "first set fires"
    assert set_alert("svc:Media", "down") is False, "second set is quiet"
    assert "svc:Media" in active_alerts()
    assert clear_alert("svc:Media") is True, "clear fires once"
    assert clear_alert("svc:Media") is False, "second clear quiet"
    log_event("recovery", "Media", "back up")
    assert recent_events()[0]["subject"] == "Media"
    set_json("base:x", ["a", "b"]); assert get_json("base:x") == ["a", "b"]
    assert get_json("nope", []) == []
    prune()
    assert len(samples_since(3600)) == 2
    print("store.py self-check passed")
