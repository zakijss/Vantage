#!/usr/bin/env python3
"""Flight and ship tracking from public feeds, for Vantage.

Aircraft come from adsb.lol, a community ADS-B aggregator with an open API and
no key. You can look at everything in a radius around a point, or follow a
specific aircraft by its ICAO hex, registration or callsign; tracking a known
tail number over time is the classic open-source technique (whose jet went
where), and it reads only the signals aircraft broadcast in the clear.

Ships use AIS, which has no good keyless feed. If DASH_AIS_KEY is set (a free
aisstream.io key) the ship side turns on; otherwise it reports that it's off.

Stdlib only. All of this is public transponder data about vehicles, not people.
"""
import bisect
import gzip
import json
import os
import re
import time
from array import array
import urllib.parse
import urllib.request

import config

ADSB = "https://api.adsb.lol/v2"
_UA = {"User-Agent": "vantage-flights"}

# The "overhead" view centres on the config's home, within a default radius in
# nautical miles.
HOME = config.get("home")
RADIUS_NM = int(config.get("flights_radius_nm", 60, env="DASH_FLIGHTS_RADIUS"))

# Aircraft to always surface if they are up, by hex or registration (upper-case).
WATCH = [w.upper() for w in config.get("flights_watch", [], env="DASH_FLIGHTS_WATCH")]


def _get(url, timeout=12):
    req = urllib.request.Request(url, headers=_UA)
    with config.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _clean(a):
    """Keep the fields a dashboard shows, with steady names."""
    return {
        "hex": a.get("hex"),
        "callsign": (a.get("flight") or "").strip() or None,
        "reg": a.get("r"),
        "type": a.get("t"),
        "alt": a.get("alt_baro"),
        "speed": a.get("gs"),
        "track": a.get("track"),
        "lat": a.get("lat"),
        "lon": a.get("lon"),
        "squawk": a.get("squawk"),
        "emergency": a.get("emergency") if a.get("emergency") not in (None, "none") else None,
        "dist_nm": round(a["dst"], 1) if isinstance(a.get("dst"), (int, float)) else None,
    }


def overhead(lat=None, lon=None, nm=None):
    """Aircraft within nm nautical miles of a point, nearest first."""
    if lat is None or lon is None:
        if not HOME:
            return {"error": "no home set in the config; pass lat and lon", "aircraft": []}
        lat, lon = float(HOME["lat"]), float(HOME["lon"])
    nm = nm or RADIUS_NM
    try:
        d = _get(f"{ADSB}/lat/{lat}/lon/{lon}/dist/{nm}")
    except Exception as e:
        return {"error": str(e)[:120], "aircraft": []}
    ac = [_clean(a) for a in d.get("ac", []) if a.get("lat") is not None]
    ac.sort(key=lambda a: (a["dist_nm"] is None, a["dist_nm"] or 0))
    emerg = [a for a in ac if a["emergency"] or (a["squawk"] in ("7500", "7600", "7700"))]
    return {"centre": [lat, lon], "radius_nm": nm, "count": len(ac),
            "emergencies": emerg, "aircraft": ac}


def _lookup(kind, value):
    try:
        d = _get(f"{ADSB}/{kind}/{urllib.parse.quote(value)}")
        return [_clean(a) for a in d.get("ac", [])]
    except Exception:
        return []


# Tickets carry the airline's IATA code (BA 117); aircraft broadcast the ICAO
# code (BAW117). North American, European, Gulf and Asian airlines.
IATA_ICAO = {
    "AA": "AAL", "UA": "UAL", "DL": "DAL", "B6": "JBU", "WN": "SWA", "AS": "ASA", "NK": "NKS",
    "F9": "FFT", "AC": "ACA", "WS": "WJA", "PD": "POE", "RV": "ROU", "QK": "JZA", "WG": "SWG",
    "TS": "TSC", "F8": "FLE", "PB": "PVL", "BA": "BAW", "VS": "VIR", "LH": "DLH", "AF": "AFR",
    "KL": "KLM", "LX": "SWR", "IB": "IBE", "AZ": "ITY", "TK": "THY", "EK": "UAE", "EY": "ETD",
    "QR": "QTR", "FZ": "FDB", "G9": "ABY", "SV": "SVA", "GF": "GFA", "WY": "OMA", "KU": "KAC",
    "MS": "MSR", "RJ": "RJA", "ET": "ETH", "SQ": "SIA", "CX": "CPA", "JL": "JAL", "NH": "ANA",
    "QF": "QFA", "AI": "AIC", "PK": "PIA", "LO": "LOT", "OS": "AUA", "SK": "SAS", "AY": "FIN",
}


def callsigns(q):
    """Callsigns worth trying for a typed flight: as typed, and with the
    airline's IATA prefix swapped for its ICAO one (with and without leading zeros)."""
    out = [q]
    m = re.fullmatch(r"([A-Z0-9]{2})(\d{1,4}[A-Z]?)", q)
    if m and m.group(1) in IATA_ICAO:
        icao = IATA_ICAO[m.group(1)]
        out += [icao + m.group(2), icao + m.group(2).lstrip("0")]
    return list(dict.fromkeys(c for c in out if c))


def find(query):
    """Find an aircraft that's currently up by hex, registration or callsign."""
    q = re.sub(r"[\s]", "", query.strip().upper())
    kind = "hex" if len(q) == 6 and all(c in "0123456789ABCDEF" for c in q) else \
           "registration" if "-" in q or (q[:1].isalpha() and any(c.isdigit() for c in q)) else "callsign"
    tried = [f"{kind} {q}"] if kind != "callsign" else []
    hits = _lookup(kind, q) if kind != "callsign" else []
    for cs in callsigns(q):
        if hits:
            break
        tried.append(f"callsign {cs}")
        hits = _lookup("callsign", cs)
        if hits:
            kind = "callsign"
    return {"query": query, "matched_by": kind, "tried": tried, "aircraft": hits}


# ---- aircraft classes, for the globe's plane shapes ---------------------------
# Transponder address -> ICAO type -> one of six shapes, from the open database
# tar1090 uses (Mictronics' readsb DB, about 620,000 aircraft). Only the address
# and type code are kept; the file's owner names are never read into memory.
ACDB_URL = "https://raw.githubusercontent.com/wiedehopf/tar1090-db/csv/aircraft.csv.gz"
TYPES_URL = "https://raw.githubusercontent.com/wiedehopf/tar1090-db/master/db/icao_aircraft_types.js"
ACDB_DIR = config.get("acdb_dir", os.path.join(config.STATE_DIR, "acdb"), env="DASH_ACDB_DIR")
ACDB_MAX_AGE = 7 * 86400
# single-aisle jets get the airliner shape; other jets the regional/business one
NARROW = re.compile(r"^(A3[12]\d|A[12][019]N|B73\d|B3[789X]M|B75\d|B712|MD[89]\d|BCS[13]|C919|T20[45]|T214)$")
_acdb = (array("I"), b"")        # sorted addresses, and a class letter for each


def type_class(code, types):
    """H heavy (wide-body or four-engine), N single-aisle airliner, R regional or
    business jet, T turboprop, L light aircraft, C helicopter or gyro, "" unknown."""
    t = types.get(code) or {}
    desc, wtc = t.get("desc", ""), t.get("wtc", "")
    if not desc:
        return ""
    if desc[0] in "HG":
        return "C"
    if wtc in ("H", "J"):
        return "H"
    eng = desc[2:3]
    if eng == "J":
        return "N" if NARROW.match(code) else "R"
    return "T" if eng == "T" else "L"


def _fetch_to(url, path):
    req = urllib.request.Request(url, headers=_UA)
    with config.urlopen(req, timeout=120) as r, open(path + ".tmp", "wb") as out:
        out.write(r.read())
    os.replace(path + ".tmp", path)


def load_acdb():
    """Refresh the database weekly and build the in-memory index (about 3 MB)."""
    global _acdb
    os.makedirs(ACDB_DIR, exist_ok=True)
    db, ty = os.path.join(ACDB_DIR, "aircraft.csv.gz"), os.path.join(ACDB_DIR, "types.js")
    fresh = all(os.path.exists(p) and time.time() - os.path.getmtime(p) < ACDB_MAX_AGE for p in (db, ty))
    if not fresh:
        _fetch_to(ACDB_URL, db)
        _fetch_to(TYPES_URL, ty)
    elif len(_acdb[0]):
        return {"aircraft": len(_acdb[0])}
    with open(ty, "rb") as fh:
        raw = fh.read()
    types = json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)
    rows = []
    with gzip.open(db, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            addr, _, rest = line.partition(";")
            code = rest.split(";", 2)[1] if rest.count(";") >= 2 else ""
            cls = type_class(code, types) if code else ""
            if cls and len(addr) == 6:
                try:
                    rows.append((int(addr, 16), cls))
                except ValueError:
                    pass
    rows.sort()
    _acdb = (array("I", (a for a, _ in rows)), "".join(c for _, c in rows).encode())
    return {"aircraft": len(rows)}


def class_of(icao24):
    """The shape class for a transponder address (hex), or "" if unknown."""
    addrs, classes = _acdb
    try:
        a = int(icao24, 16)
    except (TypeError, ValueError):
        return ""
    i = bisect.bisect_left(addrs, a)
    return chr(classes[i]) if i < len(addrs) and addrs[i] == a else ""


def watch():
    """The aircraft on the watch list that are airborne right now."""
    out = []
    for w in WATCH:
        kind = "hex" if len(w) == 6 and all(c in "0123456789ABCDEF" for c in w) else "registration"
        out.extend(_lookup(kind, w))
    return out


def ships():
    """AIS ship positions, if a key is configured. Off by default (no keyless AIS feed)."""
    key = os.environ.get("DASH_AIS_KEY", "").strip()
    if not key:
        return {"enabled": False,
                "note": "set DASH_AIS_KEY (free aisstream.io key) to turn on ship tracking"}
    # aisstream is a websocket stream, not a REST call, and is not read yet.
    return {"enabled": True, "note": "AIS key present; the aisstream feed is not read yet", "ships": []}


def board():
    """The whole panel in one object."""
    oh = overhead()
    return {"generated": round(time.time()), "overhead": oh,
            "watch": watch(), "ships": ships()}


if __name__ == "__main__":
    print(json.dumps(board(), indent=2)[:3000])
