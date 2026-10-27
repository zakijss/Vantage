#!/usr/bin/env python3
"""Alerts: Vantage tells you when something breaks and when it recovers.

Each refresh, evaluate() reads the status Vantage already builds and returns the
conditions worth knowing about: a service down, the TLS cert near expiry, the
backup gone stale, a disk filling, or an email-auth gap from recon. run() diffs
that against what was already firing (persisted in store.py), so you get one
notification when something breaks and one when it recovers, not a ping every
four seconds.

Notifications go to DASH_NOTIFY_URL if set: an ntfy topic (https://ntfy.sh/your-topic
or a self-hosted one) or any webhook that accepts a POST. If it's unset, alerts
are still tracked and logged, just not pushed.

Stdlib only.
"""
import json
import os
import re
import time
import urllib.request

import config
import store

NOTIFY_URL = config.get("notify_url", "", env="DASH_NOTIFY_URL").strip()
# An access token, for an ntfy server that requires a login.
NOTIFY_TOKEN = os.environ.get("DASH_NOTIFY_TOKEN", "").strip()
CERT_DAYS = int(config.get("alert_cert_days", 14, env="DASH_ALERT_CERT_DAYS"))
BACKUP_HOURS = int(config.get("alert_backup_hours", 36, env="DASH_ALERT_BACKUP_HOURS"))
DISK_PCT = int(config.get("alert_disk_pct", 90, env="DASH_ALERT_DISK_PCT"))
# A service must stay down this long before it alerts: restarts and blips take
# seconds, a machine's reboot into an update a few minutes.
GRACE = int(config.get("alert_grace_min", 10, env="DASH_ALERT_GRACE_MIN")) * 60
_down_since = {}   # service key -> when a check first found it down
# Findings someone has taken on: {finding prefix: who fixes it and how}. They
# stop alerting. A JSON file kept with your config, not in a database.
ACK_FILE = config.get("acks_file", os.path.join(os.path.dirname(os.path.abspath(__file__)), "acks.json"),
                      env="DASH_ACK_FILE")


def acknowledged():
    try:
        with open(ACK_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def finding_key(finding):
    """One alert per finding, keyed on its text, so two findings on one domain stay apart."""
    return "recon:" + re.sub(r"[^a-z0-9]+", "-", finding.lower()).strip("-")[:90]


def threat_key(finding):
    return "threat:" + re.sub(r"[^a-z0-9]+", "-", finding.lower()).strip("-")[:90]


def evaluate(status, recon=None, threats=None):
    """Return {key: (title, detail)} for everything currently wrong. Empty = all well."""
    bad = {}
    for s in status.get("services", []):
        if s.get("status") == "down":
            bad[f"svc:{s['name']}"] = (f"{s['name']} is down", f"{s.get('desc') or ''} not responding")
    cert = status.get("cert") or {}
    if isinstance(cert.get("days"), (int, float)) and cert["days"] < CERT_DAYS:
        bad["cert"] = ("TLS cert expiring", f"{cert.get('host','cert')} in {cert['days']} days")
    bk = status.get("backup")
    if bk and isinstance(bk.get("age"), (int, float)) and bk["age"] > BACKUP_HOURS * 3600:
        bad["backup"] = ("Backup stale", f"newest backup is {round(bk['age']/3600)} h old")
    for d in status.get("disks", []):
        if d.get("total"):
            pct = round(d["used"] / d["total"] * 100)
            if pct >= DISK_PCT:
                bad[f"disk:{d['name']}"] = (f"Disk {d['name']} at {pct}%", "running low on space")
    ack = acknowledged()
    if recon:
        for f in (recon.get("flags") or []):
            if any(f.startswith(k) for k in ack):
                continue
            bad[finding_key(f)] = ("Exposure finding", f)
    if threats:
        for f in (threats.get("flags") or []):
            if any(f.startswith(k) for k in ack):
                continue
            bad[threat_key(f)] = ("Threat intel", f)
    return bad


def notify(title, message, priority="default", tags=""):
    if not NOTIFY_URL:
        return
    try:
        headers = {"Title": title, "Priority": priority}
        if NOTIFY_TOKEN:
            headers["Authorization"] = f"Bearer {NOTIFY_TOKEN}"
        if tags:
            headers["Tags"] = tags
        req = urllib.request.Request(NOTIFY_URL, data=message.encode(), headers=headers, method="POST")
        config.urlopen(req, timeout=8).read()
    except Exception as e:
        print(f"alerts: notify failed: {e}", flush=True)


def recovered_title(key):
    kind, _, name = key.partition(":")
    return {"svc": f"{name} is back", "disk": f"Disk {name} has room again", "cert": "TLS cert renewed",
            "backup": "Backups are current again", "recon": "Exposure finding resolved",
            "threat": "Threat intel cleared"}.get(kind, f"Resolved: {key}")


def run(status, recon=None, threats=None, now=None):
    """Evaluate, then fire/clear notifications on change. Returns the current bad set."""
    now = now or time.time()
    bad = evaluate(status, recon, threats)
    firing = store.active_alerts()
    for key in [k for k in _down_since if k not in bad]:
        del _down_since[key]
    for key, (title, detail) in bad.items():
        if key.startswith("svc:") and key not in firing and now - _down_since.setdefault(key, now) < GRACE:
            continue                               # not down long enough yet
        if store.set_alert(key, detail):          # newly bad -> notify once
            store.log_event("alert", key, detail)
            notify(title, detail, priority="high", tags="warning")
    # Right after a restart the attack surface's external half hasn't run yet,
    # so its findings are missing, not fixed; leave those alerts as they are.
    pending = bool(recon and recon.get("external_pending"))
    watched = {s["name"] for s in status.get("services", [])}
    for key in list(firing):
        if pending and key.startswith("recon:"):
            continue
        if key.startswith("flight:"):              # flight_watch in server.py sets and clears these
            continue
        if key.startswith("svc:") and key[4:] not in watched:
            store.clear_alert(key)                 # taken out of the config: nothing recovered
            continue
        if key not in bad:                         # recovered -> notify once
            if store.clear_alert(key):
                store.log_event("recovery", key, firing[key].get("detail", ""))
                notify(recovered_title(key), firing[key].get("detail", ""), tags="white_check_mark")
    return bad


if __name__ == "__main__":
    import tempfile, time
    os.environ["STATE_DIR"] = tempfile.mkdtemp()
    store.DB_PATH = os.path.join(os.environ["STATE_DIR"], "vantage.db")
    st = {"services": [{"name": "Wiki", "status": "up", "desc": "Docs"},
                       {"name": "Media", "status": "down", "desc": "Media"}],
          "cert": {"host": "x", "days": 5}, "backup": {"age": 200000},
          "disks": [{"name": "Database", "total": 100, "used": 95}]}
    t0 = 1_000_000
    bad1 = run(st, now=t0)
    assert "svc:Media" in bad1 and "cert" in bad1 and "backup" in bad1 and "disk:Database" in bad1, bad1
    assert "svc:Wiki" not in bad1
    # Media only just went down: no alert yet; still down after the grace: one
    assert set(store.active_alerts()) == set(bad1) - {"svc:Media"}
    run(st, now=t0 + GRACE)
    assert set(store.active_alerts()) == set(bad1)
    # Wiki blips down for one check and back: never alerts
    st["services"][0]["status"] = "down"
    run(st, now=t0 + GRACE + 4)
    st["services"][0]["status"] = "up"
    run(st, now=t0 + GRACE + 8)
    assert "svc:Wiki" not in store.active_alerts() and "svc:Wiki" not in _down_since
    # a service taken out of the config clears without a recovery
    store.set_alert("svc:Retired", "down")
    run(st, now=t0 + GRACE + 9)
    assert "svc:Retired" not in store.active_alerts()
    assert not any(e["subject"] == "svc:Retired" for e in store.recent_events())
    # Media recovers
    st["services"][1]["status"] = "up"
    bad2 = run(st, now=t0 + GRACE + 12)
    assert "svc:Media" not in bad2 and "svc:Media" not in store.active_alerts()
    recs = [e for e in store.recent_events() if e["kind"] == "recovery"]
    assert any(e["subject"] == "svc:Media" for e in recs)
    assert recovered_title("svc:Media") == "Media is back"
    # flight_watch in server.py owns flight: alerts; run() must leave them alone
    store.set_alert("flight:C-GABC", "airborne")
    run(st, now=t0 + GRACE + 16)
    assert "flight:C-GABC" in store.active_alerts()
    # recon: each finding its own alert, and an acknowledged one stays quiet
    recon = {"flags": ["x.com: DMARC p=none (monitor only)", "x.com: Google mail is not DKIM-signed (no google._domainkey)"]}
    ackf = os.path.join(os.environ["STATE_DIR"], "acks.json")
    globals()["ACK_FILE"] = ackf
    bad3 = evaluate(st, recon)
    assert len([k for k in bad3 if k.startswith("recon:")]) == 2, bad3
    with open(ackf, "w") as f:
        json.dump({"x.com: Google mail is not DKIM-signed": "waiting on the admin"}, f)
    bad4 = evaluate(st, recon)
    assert [k for k in bad4 if k.startswith("recon:")] == ["recon:x-com-dmarc-p-none-monitor-only"], bad4
    threats = {"flags": ["CVE-2024-1086 affects Linux Kernel (linux kernel), used in ransomware: UAF"]}
    bad5 = evaluate(st, None, threats)
    assert [k for k in bad5 if k.startswith("threat:")] == ["threat:cve-2024-1086-affects-linux-kernel-linux-kernel-used-in-ransomware-uaf"], bad5
    print("alerts.py self-check passed")
