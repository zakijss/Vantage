"""A peer device read from a Beszel hub, instead of pushed by agent.py.

Beszel already collects the device's numbers, so Vantage polls the hub's API
for them. In config.json the peer names its Beszel system:

    "peer": {"name": "laptop", ..., "beszel": {"port": 8090, "system": "laptop"}}

"port" is the hub's port on the host (default 8090, Beszel's own), reached
through the host gateway as the service checks are; "system" defaults to the
peer's name. The login is a
read-only Beszel user that can see that system, in the environment as
DASH_BESZEL_USER and DASH_BESZEL_PASSWORD.

Each reading takes CPU, memory use, load, uptime, the highest temperature and
the battery from the system's live record, and the memory total once from its
latest one-minute stats record, and returns them in agent.py's shape.

  python3 beszel.py --self-test
"""
import json
import sys
import urllib.parse
import urllib.request

import config


def call(base, path, token=None, body=None):
    """One request to the hub's API; JSON in and out."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    data = json.dumps(body).encode() if body is not None else None
    with config.urlopen(urllib.request.Request(base + path, data=data, headers=headers), timeout=10) as r:
        return json.load(r)


def login(base, user, password, call=call):
    """A token for the read-only user."""
    return call(base, "/api/collections/users/auth-with-password",
                body={"identity": user, "password": password})["token"]


def reading(base, name, system, token, total_kb=0, call=call):
    """(the payload agent.py pushed, or None while Beszel has the system down;
    the memory total in kB, fetched only when total_kb is 0)."""
    q = urllib.parse.quote(f"(name='{system}')", safe="")
    items = call(base, f"/api/collections/systems/records?perPage=1&filter={q}", token)["items"]
    if not items:
        raise LookupError(f"Beszel has no system named {system} for this user")
    rec = items[0]
    if not total_kb:
        q = urllib.parse.quote(f"(system='{rec['id']}' && type='1m')", safe="")
        stats = call(base, f"/api/collections/system_stats/records?perPage=1&sort=-created&filter={q}",
                     token)["items"]
        total_kb = round(stats[0]["stats"]["m"] * 1048576) if stats else 0      # GiB -> kB
    if rec.get("status") != "up":
        return None, total_kb
    info = rec.get("info") or {}
    bat = info.get("bat") or []
    return {"name": name, "cpu": info.get("cpu", 0), "load": list(info.get("la") or [0, 0, 0]),
            "uptime": info.get("u", 0), "mem_total": total_kb,
            "mem_avail": round(total_kb * (1 - (info.get("mp") or 0) / 100)),
            "temp": info.get("dt"), "battery": bat[0] if bat else None}, total_kb


def _self_test():
    calls = []

    def fake(base, path, token=None, body=None):
        calls.append(path)
        if path.endswith("auth-with-password"):
            assert body == {"identity": "v@x", "password": "pw"} and token is None
            return {"token": "T"}
        assert token == "T", token
        if path.startswith("/api/collections/systems/"):
            assert "filter=%28name%3D%27laptop%27%29" in path, path
            return {"items": [{"id": "abc", "status": status,
                               "info": {"cpu": 12.5, "mp": 25, "la": [0.5, 0.4, 0.3], "u": 3600,
                                        "dt": 48.0, "bat": [87, 3]}}]}
        if path.startswith("/api/collections/system_stats/"):
            assert "system%3D%27abc%27" in path and "sort=-created" in path, path
            return {"items": [{"stats": {"m": 15.5}}]}
        raise AssertionError(path)

    status = "up"
    assert login("http://h:1", "v@x", "pw", call=fake) == "T"
    p, total = reading("http://h:1", "laptop", "laptop", "T", call=fake)
    assert total == 16252928 and p == {
        "name": "laptop", "cpu": 12.5, "load": [0.5, 0.4, 0.3], "uptime": 3600,
        "mem_total": 16252928, "mem_avail": 12189696, "temp": 48.0, "battery": 87}, p
    n = len(calls)
    reading("http://h:1", "laptop", "laptop", "T", total, call=fake)
    assert len(calls) == n + 1                      # the total is not fetched again
    status = "down"
    assert reading("http://h:1", "laptop", "laptop", "T", total, call=fake) == (None, total)
    try:
        reading("http://h:1", "laptop", "laptop", "T", total,
                call=lambda *a, **k: {"items": []})
        raise AssertionError("no LookupError")
    except LookupError:
        pass
    print("beszel.py self-check passed")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _self_test()
