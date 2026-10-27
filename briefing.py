"""The briefing as Vantage serves it: the latest, with the items you cleared
left out, and the last week's for the history page.

A script on the host (not part of Vantage; README.md has the format) writes
STATE_DIR/briefing/latest.json, typically every hour, and YYYY-MM-DD.json with
each day's last copy:

  {"generated": "2026-10-16T22:00+00:00", "status": "ok" | "attention",
   "headline": "...", "tiles": [...], "items": [{"id", "text", "level"}]}

Clearing an item stores its key here, in store.py. The key hashes the item's
id and its text, so a cleared item stays gone while it reads the same and
comes back when it changes (a disk gets fuller, say).

Stdlib only.
"""
import hashlib
import json
import os
import re
import time

import store

DONE_KEY = "briefing_done"
DONE_DAYS = 45                       # forget a cleared item after this long
DONE_MAX = 500                       # and never keep more than this many
KEEP_DAYS = 7                        # days the history page lists
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def item_key(item):
    # sha1 on purpose, as a fingerprint, not for security: cleared keys are
    # stored, so another algorithm would bring every cleared item back.
    text = f"{item.get('id', '')}\n{item.get('text', '')}".encode()
    return hashlib.new("sha1", text, usedforsecurity=False).hexdigest()[:12]


def done():
    marks = store.get_json(DONE_KEY, {}) or {}
    cutoff = time.time() - DONE_DAYS * 86400
    return {k: t for k, t in marks.items() if t >= cutoff}


def mark(keys, undo=False):
    marks = done()
    for k in keys:
        if not re.fullmatch(r"[0-9a-f]{12}", str(k)):
            continue
        if undo:
            marks.pop(k, None)
        else:
            marks[k] = time.time()
    if len(marks) > DONE_MAX:             # newest win: the set cannot grow without bound
        marks = dict(sorted(marks.items(), key=lambda kv: kv[1])[-DONE_MAX:])
    store.set_json(DONE_KEY, marks)
    return marks


def headline(n):
    return f"{n} thing{'s' if n != 1 else ''} need{'s' if n == 1 else ''} a look" if n else "All clear"


def with_keys(report, marks, hide_done):
    """A copy of a report with each item's key and done flag, and the status
    and headline counting only what is not cleared. With hide_done, cleared
    items are left out."""
    items = []
    for it in report.get("items") or []:
        k = item_key(it)
        if hide_done and k in marks:
            continue
        items.append({**it, "key": k, "done": k in marks})
    left = sum(1 for it in items if not it["done"])
    return {**report, "items": items, "open": left,
            "status": "attention" if left else "ok", "headline": headline(left)}


def keys_of(report):
    return [item_key(it) for it in report.get("items") or []]


def latest(folder):
    with open(os.path.join(folder, "latest.json"), "rb") as f:
        return json.load(f)


def _day_file(folder, date):
    try:
        with open(os.path.join(folder, f"{date}.json"), "rb") as f:
            r = json.load(f)
    except (OSError, ValueError):
        return None
    return r if isinstance(r, dict) and "items" in r else None     # older formats are skipped


def history(folder, days=KEEP_DAYS):
    """[{date, status, headline}] for the last days, newest first."""
    marks, out = done(), []
    for name in os.listdir(folder):
        stem, ext = os.path.splitext(name)
        if ext == ".json" and DATE.match(stem):
            r = _day_file(folder, stem)
            if r is not None:
                v = with_keys(r, marks, hide_done=False)
                out.append({"date": stem, "status": v["status"], "headline": v["headline"]})
    return sorted(out, key=lambda e: e["date"], reverse=True)[:days]


def day(folder, date):
    """One day's last briefing, every item with its done flag. None if there is no such day."""
    if not DATE.match(date or ""):
        return None
    r = _day_file(folder, date)
    return None if r is None else with_keys(r, done(), hide_done=False)


if __name__ == "__main__":
    import tempfile
    store.DB_PATH = os.path.join(tempfile.mkdtemp(), "v.db")
    rep = {"status": "attention", "headline": "2 things need a look", "tiles": [],
           "items": [{"id": "disk:Data", "text": "Data disk is 91% full", "level": "warn"},
                     {"id": "peer", "text": "the peer didn't answer", "level": "warn"}]}
    k = keys_of(rep)
    assert len(k) == 2 and k[0] == item_key(rep["items"][0])
    mark([k[0]])
    v = with_keys(rep, done(), hide_done=True)
    assert v["headline"] == "1 thing needs a look" and v["open"] == 1 and len(v["items"]) == 1, v
    # the same item with new text is a new item: it comes back
    rep2 = {**rep, "items": [{**rep["items"][0], "text": "Data disk is 92% full"}, rep["items"][1]]}
    assert with_keys(rep2, done(), hide_done=True)["open"] == 2
    mark(k)
    v = with_keys(rep, done(), hide_done=True)
    assert v["status"] == "ok" and v["headline"] == "All clear" and v["items"] == []
    v = with_keys(rep, done(), hide_done=False)            # history keeps them, marked done
    assert [i["done"] for i in v["items"]] == [True, True] and v["open"] == 0
    mark([k[1]], undo=True)
    assert with_keys(rep, done(), hide_done=True)["open"] == 1
    mark(["../../etc", "zz"])                        # not keys: ignored
    assert set(done()) == {k[0]}
    for i in range(0, 700, 100):                     # the set is capped
        mark([f"{n:012x}" for n in range(i, i + 100)])
    assert len(done()) == DONE_MAX
    d = tempfile.mkdtemp()
    json.dump(rep, open(os.path.join(d, "2026-10-12.json"), "w"))
    json.dump({"sections": []}, open(os.path.join(d, "2026-10-11.json"), "w"))      # an older format
    h = history(d)
    assert [e["date"] for e in h] == ["2026-10-12"], h
    assert day(d, "2026-10-12")["items"][0]["key"] == k[0]
    assert day(d, "2026-10-11") is None and day(d, "../latest") is None
    print("briefing.py self-check passed")
