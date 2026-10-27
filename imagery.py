#!/usr/bin/env python3
"""Image-verification helpers for Vantage: the open-source investigation kind.

Three jobs, all on an image or a place you already have, none of them about a
person:
  - exif(bytes)        read a JPEG's metadata, above all any GPS the camera wrote
  - sun(lat, lon, utc) where the sun sits in the sky there and then, for reading
                       shadows (chronolocation): a shadow's direction and length
                       pin a time of day once you know the place and date
  - place(lat, lon)    the nearest named place for a coordinate (OpenStreetMap)

Pure stdlib, so it runs in Vantage's container: the EXIF reader parses the
JPEG/TIFF structure by hand rather than leaning on Pillow.
"""
import datetime
import json
import math
import struct
import urllib.parse
import urllib.request

import config

_UA = {"User-Agent": "vantage-imagery"}

# the EXIF/TIFF and GPS tags worth naming
_TAGS = {0x010F: "make", 0x0110: "model", 0x0112: "orientation",
         0x0132: "datetime", 0x9003: "datetime_original", 0x8827: "iso",
         0x920A: "focal_length", 0xA002: "width", 0xA003: "height",
         0x8769: "_exif_ifd", 0x8825: "_gps_ifd"}
_GPS = {1: "lat_ref", 2: "lat", 3: "lon_ref", 4: "lon", 5: "alt_ref",
        6: "alt", 7: "timestamp", 29: "datestamp", 16: "img_dir_ref", 17: "img_dir"}
_FMT = {1: ("B", 1), 2: ("s", 1), 3: ("H", 2), 4: ("I", 4), 5: ("II", 8),
        7: ("s", 1), 9: ("i", 4), 10: ("ii", 8)}


def _ifd(buf, off, order):
    """Parse one TIFF IFD at offset `off`; returns {tag: value}."""
    out = {}
    try:
        (n,) = struct.unpack(order + "H", buf[off:off + 2])
    except struct.error:
        return out
    p = off + 2
    for _ in range(n):
        entry = buf[p:p + 12]
        p += 12
        if len(entry) < 12:
            break
        tag, typ, count = struct.unpack(order + "HHI", entry[:8])
        if typ not in _FMT:
            continue
        code, size = _FMT[typ]
        total = size * count
        raw = entry[8:12] if total <= 4 else buf[struct.unpack(order + "I", entry[8:12])[0]:][:total]
        if len(raw) < total:  # runs past the file; a huge count would build a huge format
            continue
        if typ in (2,):  # ASCII
            out[tag] = raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
        elif typ in (5, 10):  # rationals
            vals = []
            for i in range(count):
                num, den = struct.unpack(order + ("II" if typ == 5 else "ii"), raw[i * 8:i * 8 + 8])
                vals.append(num / den if den else 0.0)
            out[tag] = vals if count > 1 else (vals[0] if vals else None)
        else:
            try:
                vals = list(struct.unpack(order + code * count, raw[:total]))
                out[tag] = vals if count > 1 else vals[0]
            except struct.error:
                pass
    return out


def _dms(vals, ref):
    """GPS degrees/minutes/seconds triple + hemisphere ref -> signed decimal."""
    if not vals or len(vals) < 3:
        return None
    dec = vals[0] + vals[1] / 60 + vals[2] / 3600
    return -dec if str(ref).upper() in ("S", "W") else dec


def exif(data):
    """Metadata from JPEG bytes. Always returns a dict; {} fields mean 'not present'."""
    try:
        return _exif(data)
    except (struct.error, ValueError, TypeError, AttributeError, IndexError):
        return {"error": "malformed EXIF"}


def _exif(data):
    if data[:2] != b"\xff\xd8":
        return {"error": "not a JPEG"}
    # find the APP1 Exif segment
    i, app1 = 2, None
    while i < len(data) - 4:
        if data[i] != 0xFF:
            break
        marker, seglen = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
        seg = data[i + 4:i + 2 + seglen]
        if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            app1 = seg[6:]
            break
        if marker == 0xDA:  # start of scan: pixel data follows, no more headers
            break
        i += 2 + seglen
    if not app1:
        return {"present": False}
    order = "<" if app1[:2] == b"II" else ">"
    ifd0_off = struct.unpack(order + "I", app1[4:8])[0]
    ifd0 = _ifd(app1, ifd0_off, order)
    tags = {}
    for t, name in _TAGS.items():
        if t in ifd0 and not name.startswith("_"):
            tags[name] = ifd0[t]
    if 0x8769 in ifd0:  # Exif sub-IFD
        for t, v in _ifd(app1, ifd0[0x8769], order).items():
            if t in _TAGS and not _TAGS[t].startswith("_"):
                tags[_TAGS[t]] = v
    gps = {}
    if 0x8825 in ifd0:
        g = _ifd(app1, ifd0[0x8825], order)
        named = {_GPS[t]: v for t, v in g.items() if t in _GPS}
        lat = _dms(named.get("lat"), named.get("lat_ref"))
        lon = _dms(named.get("lon"), named.get("lon_ref"))
        if lat is not None and lon is not None:
            gps = {"lat": round(lat, 6), "lon": round(lon, 6)}
            if "alt" in named:
                gps["alt_m"] = round(named["alt"] * (-1 if named.get("alt_ref") == 1 else 1), 1)
            if "img_dir" in named:
                gps["heading"] = round(named["img_dir"], 1)
            if "datestamp" in named and "timestamp" in named:
                ts = named["timestamp"]
                if isinstance(ts, list) and len(ts) == 3:
                    gps["utc"] = f"{named['datestamp'].replace(':', '-')} " \
                                 f"{int(ts[0]):02d}:{int(ts[1]):02d}:{int(ts[2]):02d}Z"
    return {"present": True, "tags": tags, "gps": gps or None}


def sun(lat, lon, when=None):
    """Solar azimuth and elevation (degrees) at a place and UTC time (NOAA algorithm).

    Azimuth is clockwise from north; a shadow points the opposite way, which is
    what lets a shadow in a photo fix the time once place and date are known."""
    if when is None:
        when = datetime.datetime.now(datetime.timezone.utc)
    elif isinstance(when, str):
        when = datetime.datetime.fromisoformat(when.replace("Z", "+00:00"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    jd = when.timestamp() / 86400.0 + 2440587.5
    n = jd - 2451545.0
    L = (280.460 + 0.9856474 * n) % 360
    g = math.radians((357.528 + 0.9856003 * n) % 360)
    lam = math.radians(L + 1.915 * math.sin(g) + 0.020 * math.sin(2 * g))
    eps = math.radians(23.439 - 0.0000004 * n)
    dec = math.asin(math.sin(eps) * math.sin(lam))
    ra = math.atan2(math.cos(eps) * math.sin(lam), math.cos(lam))
    gmst = (18.697374558 + 24.06570982441908 * n) % 24
    lst = math.radians((gmst * 15 + lon) % 360)
    ha = lst - ra
    la = math.radians(lat)
    el = math.asin(math.sin(la) * math.sin(dec) + math.cos(la) * math.cos(dec) * math.cos(ha))
    az = math.atan2(-math.sin(ha), math.tan(dec) * math.cos(la) - math.sin(la) * math.cos(ha))
    return {"azimuth": round(math.degrees(az) % 360, 1),
            "elevation": round(math.degrees(el), 1),
            "shadow_dir": round((math.degrees(az) + 180) % 360, 1),
            "utc": when.astimezone(datetime.timezone.utc).isoformat()}


def place(lat, lon):
    """Nearest named place for a coordinate, from OpenStreetMap's reverse geocoder."""
    try:
        q = urllib.parse.urlencode({"lat": lat, "lon": lon, "format": "json", "zoom": 14})
        req = urllib.request.Request(f"https://nominatim.openstreetmap.org/reverse?{q}", headers=_UA)
        with config.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())
        return {"name": d.get("display_name"), "address": d.get("address", {})}
    except Exception as e:
        return {"error": str(e)[:120]}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(json.dumps(exif(open(sys.argv[1], "rb").read()), indent=2))
    else:
        print(json.dumps(sun(51.48, 0.0), indent=2))
