"""Vantage's settings: one JSON file, so nothing about your own machines lives
in the code. The path is VANTAGE_CONFIG, or config.json beside server.py.
Every setting has a generic default, so Vantage starts with no file at all.

A setting can also come from the environment variable named for it in
README.md; the environment wins. Secrets (DASH_TOKEN, DASH_NOTIFY_TOKEN and the
API keys) are read from the environment only, never from this file.

The file is checked at start-up; a wrong type, a misspelt key or a service
without a port stops Vantage with a list of what to fix.

  python3 config.py --self-test

Stdlib only.
"""
import json
import os
import re
import sys
import urllib.request

# Every fetch goes through this: http and https only, so a URL from a setting,
# a feed or a request can't read a local file (file://) or use ftp:// or data:.
_web = urllib.request.OpenerDirector()
for _h in (urllib.request.UnknownHandler, urllib.request.HTTPHandler, urllib.request.HTTPSHandler,
           urllib.request.HTTPRedirectHandler, urllib.request.HTTPDefaultErrorHandler,
           urllib.request.HTTPErrorProcessor):
    _web.add_handler(_h())
urlopen = _web.open

# Where history, alert state and the files host scripts write go.
STATE_DIR = os.environ.get("STATE_DIR", "/state")

PATH = os.environ.get("VANTAGE_CONFIG") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config.json")

# Every key Vantage reads, with the JSON type it takes. README.md says what each does.
NUM, TEXT, LIST, OBJ, BOOL = (int, float), str, list, dict, bool
KEYS = {
    "host": OBJ, "peer": OBJ, "services": LIST, "service_host": TEXT, "gateway_probe_port": int,
    "origin": TEXT, "owners": LIST, "dashboard": OBJ, "history_link": OBJ, "home": OBJ,
    "cities": LIST, "disks": LIST, "backup_path": TEXT, "cert": OBJ, "notify_url": TEXT,
    "alert_cert_days": NUM, "alert_backup_hours": NUM, "alert_disk_pct": NUM, "alert_grace_min": NUM,
    "acks_file": TEXT, "retain_days": NUM, "tailnet_domain": TEXT, "exposure_file": TEXT,
    "expected_open": LIST, "expected_public": LIST, "recon_domains": LIST, "recon_emails": LIST,
    "threat_watch": LIST, "threat_kev_days": NUM, "ransomware_url": TEXT, "flights_radius_nm": NUM,
    "flights_watch": LIST, "acdb_dir": TEXT, "security_dir": TEXT, "scans": LIST, "cables_api": TEXT,
    "constellation": BOOL,
}
_NAMES = {NUM: "a number", int: "a whole number", TEXT: "a string", LIST: "a list", OBJ: "an object",
          BOOL: "true or false"}


def _is(value, kind):
    # bool is a subclass of int, so true would pass as a number without this
    return isinstance(value, kind) and (kind is bool or not isinstance(value, bool))


def validate(cfg):
    """A list of problems with a parsed config, each naming the key; empty when
    it is fine. Unknown keys are reported too, since they are usually typos."""
    if not isinstance(cfg, dict):
        return ["the file must hold one JSON object, {...}"]
    bad = []
    for key, value in cfg.items():
        kind = KEYS.get(key)
        if kind is None:
            bad.append(f"{key}: not a setting Vantage knows (a typo?)")
        elif value is not None and not _is(value, kind):
            bad.append(f"{key}: must be {_NAMES[kind]}")

    def items(key):
        value = cfg.get(key)
        return enumerate(value if _is(value, list) else [])

    def each(key, need):
        for i, item in items(key):
            where = f"{key}[{i}]"
            if not isinstance(item, dict):
                bad.append(f"{where}: must be an object")
                continue
            for field, kind in need.items():
                if not _is(item.get(field), kind):
                    bad.append(f"{where}: needs \"{field}\", {_NAMES[kind]}")

    each("services", {"name": TEXT, "port": int})
    each("disks", {"name": TEXT, "path": TEXT})
    each("cities", {"name": TEXT, "tz": TEXT})
    each("scans", {"id": TEXT})
    for i, s in items("scans"):
        if isinstance(s, dict) and _is(s.get("id"), TEXT) and not re.fullmatch(r"[a-z0-9_-]{1,40}", s["id"]):
            bad.append(f"scans[{i}]: \"id\" may only hold a-z, 0-9, _ and - (it names a file)")
    home = cfg.get("home")
    if _is(home, dict) and not (_is(home.get("lat"), NUM) and _is(home.get("lon"), NUM)):
        bad.append("home: needs \"lat\" and \"lon\", numbers")
    peer = cfg.get("peer")
    if _is(peer, dict) and not _is(peer.get("name"), TEXT):
        bad.append("peer: needs \"name\", a string")
    return bad


def _load():
    try:
        with open(PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        if os.environ.get("VANTAGE_CONFIG"):
            raise SystemExit(f"VANTAGE_CONFIG is {PATH}, which does not exist")
        print(f"config: no {PATH}, starting with the defaults", flush=True)
        return {}
    except ValueError as e:
        raise SystemExit(f"{PATH}: not valid JSON: {e}")
    except OSError as e:          # a directory, say, where a container mount found no file
        raise SystemExit(f"{PATH}: cannot read it: {e.strerror}")
    bad = validate(cfg)
    if bad:
        raise SystemExit(f"{PATH} has {len(bad)} problem{'s' if len(bad) > 1 else ''}:\n  " + "\n  ".join(bad))
    return cfg


CFG = _load()


def get(key, default=None, env=None):
    """The environment variable `env` when it is set, else the file, else default.
    A list setting takes its environment value comma-separated."""
    raw = os.environ.get(env, "").strip() if env else ""
    if raw:
        if isinstance(default, list):
            return [x.strip() for x in raw.split(",") if x.strip()]
        if isinstance(default, int):
            try:
                return int(raw)
            except ValueError:
                raise SystemExit(f"{env}: must be a whole number, not {raw!r}")
        return raw
    value = CFG.get(key)
    return default if value is None else value


if __name__ == "__main__" and "--self-test" in sys.argv:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.example.json")) as f:
        assert validate(json.load(f)) == []
    assert validate({}) == [] and validate([]) == ["the file must hold one JSON object, {...}"]
    assert validate({"retain_days": "30"}) == ["retain_days: must be a number"]
    assert validate({"alert_disk_pct": True}) == ["alert_disk_pct: must be a number"]
    assert validate({"constellation": True}) == []
    assert validate({"constellation": 1}) == ["constellation: must be true or false"]
    assert validate({"sevices": []}) == ["sevices: not a setting Vantage knows (a typo?)"]
    assert validate({"services": [{"name": "A", "port": "80"}, "x"]}) == [
        'services[0]: needs "port", a whole number', "services[1]: must be an object"]
    assert validate({"scans": [{"id": "../x"}]}) == [
        'scans[0]: "id" may only hold a-z, 0-9, _ and - (it names a file)']
    assert validate({"home": {"name": "X"}, "peer": {}}) == [
        'home: needs "lat" and "lon", numbers', 'peer: needs "name", a string']
    os.environ["X_TEST"] = "a, b,"
    assert get("nope", [], env="X_TEST") == ["a", "b"]
    print("config.py self-check passed")
