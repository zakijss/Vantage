"""Submarine cables for the map layer, from TeleGeography's Submarine Cable Map
(https://www.submarinecablemap.com). That data is CC BY-NC-SA 3.0, so it is
not in the repository: refresh() fetches it once at start-up, converts it to
the small shape index.html draws, and caches it as STATE_DIR/cables.json. The
page loads it as /static/cables.json. If the fetch fails the cached copy
stays; with no cached copy the layer is empty.

Set cables_api to "" to turn the fetch off.

  python3 cables.py --self-test

Stdlib only.
"""
import json
import os
import sys
import time
import urllib.request

import config

API = config.get("cables_api", "https://www.submarinecablemap.com/api/v3",
                 env="DASH_CABLES_API").strip().rstrip("/")
PATH = os.path.join(config.STATE_DIR, "cables.json")


def convert(cable_geo, landing_geo):
    """TeleGeography's two GeoJSON files to {"cables": [{id, n, c, l}],
    "landing": [[lon, lat, name, id]]}, coordinates to 3 decimals (about 100 m).
    A cable split over several features becomes one entry."""
    cables = {}
    for f in cable_geo["features"]:
        p, g = f["properties"], f["geometry"]
        if g["type"] != "MultiLineString":
            continue
        c = cables.setdefault(p["id"], {"id": p["id"], "n": p["name"], "c": p.get("color") or "#939597", "l": []})
        c["l"] += [[[round(pt[0], 3), round(pt[1], 3)] for pt in line] for line in g["coordinates"]]
    landing = []
    for f in landing_geo["features"]:
        p = f["properties"]
        if p.get("is_tbd") or f["geometry"]["type"] != "Point":
            continue
        lon, lat = f["geometry"]["coordinates"][:2]
        landing.append([round(lon, 3), round(lat, 3), p["name"], p["id"]])
    return {"source": f"TeleGeography Submarine Cable Map, CC BY-NC-SA 3.0, fetched {time.strftime('%Y-%m-%d')}",
            "cables": list(cables.values()), "landing": landing}


def _get(path):
    req = urllib.request.Request(API + path, headers={"User-Agent": "vantage-cables"})
    with config.urlopen(req, timeout=60) as r:
        return json.load(r)


def refresh():
    """Fetch, convert and cache. Runs in a thread at start-up; logs one line."""
    if not API:
        return
    try:
        data = convert(_get("/cable/cable-geo.json"), _get("/landing-point/landing-point-geo.json"))
        if not data["cables"]:
            raise ValueError("no cables in the reply")
        os.makedirs(os.path.dirname(PATH), exist_ok=True)
        with open(PATH + ".tmp", "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
        os.replace(PATH + ".tmp", PATH)
        print(f"cables: {len(data['cables'])} cables, {len(data['landing'])} landing points from TeleGeography", flush=True)
    except Exception as e:
        kept = "using the cached copy" if os.path.exists(PATH) else "the cable layer is empty"
        print(f"cables: fetch failed ({type(e).__name__}: {e}), {kept}", flush=True)


if __name__ == "__main__" and "--self-test" in sys.argv:
    geo = {"features": [
        {"properties": {"id": "a", "name": "A", "color": "#123456"},
         "geometry": {"type": "MultiLineString", "coordinates": [[[1.23456, 2.0], [3.0, 4.0]]]}},
        {"properties": {"id": "a", "name": "A"},
         "geometry": {"type": "MultiLineString", "coordinates": [[[5.0, 6.0], [7.0, 8.0]]]}},
        {"properties": {"id": "b", "name": "B"}, "geometry": {"type": "Point", "coordinates": [0, 0]}},
    ]}
    pts = {"features": [
        {"properties": {"id": "cork", "name": "Cork, Ireland", "is_tbd": False},
         "geometry": {"type": "Point", "coordinates": [-8.47277, 51.89833]}},
        {"properties": {"id": "tbd", "name": "TBD", "is_tbd": True},
         "geometry": {"type": "Point", "coordinates": [0, 0]}},
    ]}
    out = convert(geo, pts)
    assert out["cables"] == [{"id": "a", "n": "A", "c": "#123456",
                              "l": [[[1.235, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]]}], out["cables"]
    assert out["landing"] == [[-8.473, 51.898, "Cork, Ireland", "cork"]], out["landing"]
    assert out["source"].startswith("TeleGeography")
    print("cables.py self-check passed")
