"""The Security page's data: each host's weekly Lynis summaries and the last
week's security alerts, read from one folder that a script on the host fills
(README.md has the format):

  <host>-YYYY-MM-DD.json   one Lynis summary per host per run
  alerts.json              {"generated", "alerts": [{"id", "time", "host", "text", "priority"}]}

Vantage only reads them. Stdlib only.
"""
import json
import os
import re
import time

NAME = re.compile(r"^(.+)-(\d{4}-\d{2}-\d{2})\.json$")
ALERT_DAYS = 7


def _load(path):
    try:
        with open(path, "rb") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _items(s):
    """{(test ID, text): item} over a summary's warnings and suggestions."""
    out = {}
    for kind in ("warnings", "suggestions"):
        for i in s.get(kind) or []:
            if isinstance(i, dict):
                out[(i.get("id", ""), i.get("text", ""))] = {**i, "kind": kind[:-1]}
    return out


def report(folder, now=None):
    """{"hosts": [...], "alerts": [...]}. Per host: the latest summary with each
    item marked new when the run before didn't have it, what that run had and
    this one doesn't (resolved, leaving out the tests now accepted on purpose),
    the accepted tests with their reasons, and the hardening index of every run kept."""
    now = time.time() if now is None else now
    runs = {}
    try:
        names = os.listdir(folder)
    except OSError:
        names = []
    for name in names:
        m = NAME.match(name)
        s = _load(os.path.join(folder, name)) if m else None
        if isinstance(s, dict):
            runs.setdefault(m[1], []).append((m[2], s))
    hosts = []
    for host, rs in sorted(runs.items()):
        rs.sort(key=lambda r: r[0])
        date, latest = rs[-1]
        prev = _items(rs[-2][1]) if len(rs) > 1 else None
        mark = lambda i: {**i, "new": prev is not None and (i.get("id", ""), i.get("text", "")) not in prev}
        now_keys = _items(latest)
        accepted = [a for a in latest.get("accepted") or [] if isinstance(a, dict)]
        acc_ids = {str(a.get("id", "")).split(":")[0] for a in accepted}
        hosts.append({
            "host": host, "date": date, "previous": rs[-2][0] if len(rs) > 1 else None,
            "lynis": latest.get("lynis"), "os": latest.get("os"), "index": latest.get("index"),
            "tests": latest.get("tests"), "started": latest.get("started"),
            "warnings": [mark(i) for i in latest.get("warnings") or [] if isinstance(i, dict)],
            "suggestions": [mark(i) for i in latest.get("suggestions") or [] if isinstance(i, dict)],
            "resolved": [i for k, i in (prev or {}).items() if k not in now_keys and k[0] not in acc_ids],
            "accepted": accepted,
            "history": [{"date": d, "index": s.get("index")} for d, s in rs]})
    a = _load(os.path.join(folder, "alerts.json"))
    alerts = [x for x in (a.get("alerts") if isinstance(a, dict) else None) or []
              if isinstance(x, dict) and isinstance(x.get("time"), (int, float)) and x["time"] >= now - ALERT_DAYS * 86400]
    alerts.sort(key=lambda x: x["time"], reverse=True)
    return {"hosts": hosts, "alerts": alerts}


if __name__ == "__main__":
    import tempfile
    d = tempfile.mkdtemp()
    w = lambda name, obj: json.dump(obj, open(os.path.join(d, name), "w"))
    item = lambda i, t: {"id": i, "text": t, "details": "", "solution": "", "category": "Kernel", "description": ""}
    w("box-2026-10-10.json", {"index": 80, "warnings": [item("AUTH-9216", "grpck")],
                              "suggestions": [item("KRNL-5820", "core dumps"), item("SSH-7408", "port"),
                                              item("FILE-6362", "tmp")]})
    w("box-2026-10-17.json", {"index": 82, "lynis": "3.1.7", "warnings": [item("AUTH-9216", "grpck")],
                              "suggestions": [item("KRNL-5820", "core dumps"), item("NAME-4028", "dns")],
                              "accepted": [{"id": "SSH-7408:port", "reason": "tailnet only"}, "junk"]})
    w("other-2026-10-17.json", {"index": 81, "warnings": [], "suggestions": [item("X-1", "x")]})
    w("broken-2026-10-17.json", [])                                 # not a summary: skipped
    open(os.path.join(d, "junk-2026-10-03.json"), "w").write("{")  # not JSON: skipped
    w("alerts.json", {"alerts": [{"id": "a", "time": 1000, "host": "box", "text": "old"},
                                 {"id": "b", "time": 9 * 86400, "host": "box", "text": "SELinux denial"},
                                 {"id": "c", "time": 8 * 86400, "host": "other", "text": "failed ssh login"}]})
    r = report(d, now=10 * 86400)
    box, other = r["hosts"]
    assert [h["host"] for h in r["hosts"]] == ["box", "other"]
    assert box["date"] == "2026-10-17" and box["previous"] == "2026-10-10" and box["index"] == 82
    assert box["history"] == [{"date": "2026-10-10", "index": 80}, {"date": "2026-10-17", "index": 82}]
    assert [i["new"] for i in box["warnings"]] == [False]
    assert [(i["id"], i["new"]) for i in box["suggestions"]] == [("KRNL-5820", False), ("NAME-4028", True)]
    assert [(i["id"], i["kind"]) for i in box["resolved"]] == [("FILE-6362", "suggestion")]   # SSH-7408 is accepted
    assert box["accepted"] == [{"id": "SSH-7408:port", "reason": "tailnet only"}] and other["accepted"] == []
    assert other["previous"] is None and other["resolved"] == [] and not other["suggestions"][0]["new"]
    assert [a["id"] for a in r["alerts"]] == ["b", "c"], r["alerts"]
    assert report(os.path.join(d, "missing")) == {"hosts": [], "alerts": []}
    print("security.py self-check passed")
