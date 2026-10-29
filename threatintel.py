#!/usr/bin/env python3
"""Defensive threat intelligence for Vantage, scoped to what you run and own.

It reads public threat feeds and keeps only what touches the software,
domains and addresses you list. It never takes a third party as a target.

  CISA KEV   The Known Exploited Vulnerabilities catalogue (keyless). An entry
             whose product matches your watchlist (DASH_THREAT_WATCH, default
             below) becomes a flag when it was added in the last
             threat_kev_days days. Older entries are listed, not flagged.

  Leak sites Optional. If ransomware_url is set to a reachable feed of
             recently posted victims (ransomware.live or a mirror), a victim
             whose name matches one of your own domains is flagged. Off and
             silent without the URL; it is an early warning about your own org,
             not a roster of other people's breaches.

  Breaches   Only your own addresses, the accounts in recon_emails: Have I
             Been Pwned with DASH_HIBP_KEY set, otherwise XposedOrNot, which is
             free and keyless. A flag names the breaches, so clearing it in the
             briefing holds until a new breach changes the list.

Flags flow into alerts.run() keyed threat:, so acks.json can quiet a known one
and the briefing lists the rest.
"""
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import config

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_DAYS = int(config.get("threat_kev_days", 14, env="DASH_THREAT_KEV_DAYS"))
# The software you run, so KEV matches to it. Whole-word, case-insensitive.
WATCH = [w.strip().lower() for w in config.get("threat_watch", [
    "linux kernel", "openssh", "docker", "podman", "nginx", "caddy", "postgresql", "redis",
], env="DASH_THREAT_WATCH") if w.strip()]
RANSOMWARE_URL = config.get("ransomware_url", "", env="DASH_RANSOMWARE_URL").strip()
HIBP_KEY = os.environ.get("DASH_HIBP_KEY", "").strip()
EMAILS = config.get("recon_emails", [], env="DASH_RECON_EMAILS")
DOMAINS = [d.lower() for d in config.get("recon_domains", [], env="DASH_RECON_DOMAINS")]

_UA = {"User-Agent": "vantage-threatintel"}


def _get_json(url, timeout=25, headers=None):
    req = urllib.request.Request(url, headers={**_UA, **(headers or {})})
    with config.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _safe_err(e):
    """A short reason with no URL in it. A raw urllib error stringifies the whole
    request URL, which can carry an API key (ransomware_url) or your own
    address (the HIBP path), and this value is served and logged."""
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}"
    if isinstance(e, urllib.error.URLError):
        return f"unreachable ({type(e.reason).__name__})"
    return type(e).__name__


def _age_days(date_str, now):
    """Whole days since an ISO date like 2026-10-08. None if unparseable."""
    try:
        t = time.strptime(date_str[:10], "%Y-%m-%d")
        return (now - time.mktime(t)) / 86400
    except (ValueError, TypeError):
        return None


def kev_findings(vulns, watch, days, now):
    """Pure logic, so it is testable without the network. Returns recent entries,
    entries that match the watchlist, and the alert-worthy flags among them."""
    terms = [w for w in watch if w]
    recent, matches, flags = [], [], []
    for v in vulns:
        hay = " ".join((v.get("vendorProject", ""), v.get("product", ""),
                        v.get("vulnerabilityName", ""))).lower()
        hit = next((w for w in terms if re.search(r"\b" + re.escape(w) + r"\b", hay)), None)
        age = _age_days(v.get("dateAdded", ""), now)
        ransom = v.get("knownRansomwareCampaignUse", "").lower() == "known"
        row = {"cve": v.get("cveID"), "product": (v.get("vendorProject", "") + " " + v.get("product", "")).strip(),
               "name": v.get("vulnerabilityName", "").strip(), "added": v.get("dateAdded"),
               "ransomware": ransom, "match": hit}
        if age is not None and age <= days:
            recent.append(row)
        if hit:
            matches.append(row)
            # Alert only when it is newly listed. An old entry is long patched in
            # software that updates itself (podman auto-update, rpm-ostree), so
            # flagging it, ransomware or not, would only be noise.
            if age is not None and age <= days:
                tail = ", used in ransomware" if ransom else ""
                flags.append(f"{row['cve']} affects {row['product']} ({hit}){tail}: {row['name']}")
    return recent, matches, flags


def ransomware_hits(victims, domains):
    """Victims whose name or domain matches one of yours. victims: list of dicts."""
    out = []
    for v in victims or []:
        blob = json.dumps(v).lower()
        hit = next((d for d in domains if d and d in blob), None)
        if hit:
            group = v.get("group_name") or v.get("group") or "?"
            out.append(f"your domain {hit} appears on a ransomware leak site ({group})")
    return out


def xon_names(data):
    """Breach names from an XposedOrNot check-email reply. It answers 200 for
    both outcomes: {"breaches": [[names]]} or {"Error": "Not found"}."""
    rows = (data or {}).get("breaches") or []
    return [n for row in rows for n in (row if isinstance(row, list) else [row]) if n]


def _breaches():
    """Your own addresses only. Returns a list of flag strings."""
    if not EMAILS:
        return []
    out = []
    for addr in EMAILS:
        if not HIBP_KEY:
            names = xon_names(_get_json("https://api.xposedornot.com/v1/check-email/"
                                        + urllib.parse.quote(addr), timeout=20))
            if names:
                names = sorted(names)        # the count changes with any new breach, so a tick lifts
                more = f" and {len(names) - 8} more" if len(names) > 8 else ""
                out.append(f"{addr} appears in {len(names)} breach(es): {', '.join(names[:8])}{more}")
            time.sleep(1.5)          # XposedOrNot allows about one a second
            continue
        try:
            data = _get_json(
                "https://haveibeenpwned.com/api/v3/breachedaccount/"
                + urllib.parse.quote(addr) + "?truncateResponse=false",
                headers={"hibp-api-key": HIBP_KEY}, timeout=15)
        except urllib.error.HTTPError as e:
            if e.code == 404:        # not found in any breach: good
                continue
            raise
        names = ", ".join(b.get("Name", "?") for b in data[:6])
        out.append(f"{addr} appears in {len(data)} breach(es): {names}")
        time.sleep(1.7)              # HIBP asks for ~1 req/1.5s
    return out


def gather():
    now = time.time()
    out = {"generated": round(now), "watch": WATCH, "recent": [], "matches": [],
           "ransomware": [], "breaches": [], "flags": [], "errors": []}
    try:
        cat = _get_json(KEV_URL)
        out["kev_version"] = cat.get("catalogVersion")
        out["kev_count"] = cat.get("count")
        out["recent"], out["matches"], kev_flags = kev_findings(
            cat.get("vulnerabilities", []), WATCH, KEV_DAYS, now)
        out["flags"] += kev_flags
    except Exception as e:
        out["errors"].append(f"kev: {_safe_err(e)}")
    if RANSOMWARE_URL:
        try:
            data = _get_json(RANSOMWARE_URL, timeout=20)
            victims = data if isinstance(data, list) else data.get("data", [])
            out["ransomware"] = ransomware_hits(victims, DOMAINS)
            out["flags"] += out["ransomware"]
        except Exception as e:
            out["errors"].append(f"ransomware: {_safe_err(e)}")
    try:
        out["breaches"] = _breaches()
        out["flags"] += out["breaches"]
    except Exception as e:
        out["errors"].append(f"breaches: {_safe_err(e)}")
    return out


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        now = time.mktime(time.strptime("2026-10-11", "%Y-%m-%d"))
        vulns = [
            {"cveID": "CVE-1", "vendorProject": "ISC", "product": "BIND",
             "vulnerabilityName": "DoS", "dateAdded": "2026-10-08", "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": "CVE-2", "vendorProject": "Example", "product": "Wikiware",
             "vulnerabilityName": "Auth bypass", "dateAdded": "2026-10-09", "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": "CVE-3", "vendorProject": "Acme", "product": "Gridhub server",
             "vulnerabilityName": "RCE", "dateAdded": "2020-01-01", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-4", "vendorProject": "Acme", "product": "Widget",
             "vulnerabilityName": "XSS", "dateAdded": "2026-10-10", "knownRansomwareCampaignUse": "Unknown"},
        ]
        recent, matches, flags = kev_findings(vulns, ["wikiware", "gridhub"], 14, now)
        assert {r["cve"] for r in recent} == {"CVE-1", "CVE-2", "CVE-4"}, recent     # within 14 days
        assert {m["cve"] for m in matches} == {"CVE-2", "CVE-3"}, matches            # watchlist hits
        # CVE-2 is recent and matches -> flagged; CVE-3 matches but is old -> listed, not flagged
        assert {f.split()[0] for f in flags} == {"CVE-2"}, flags
        # a word match, not a substring: "linux kernel" must not hit "cloudlinux"
        _, m2, _ = kev_findings([{"cveID": "X", "product": "CloudLinux", "vulnerabilityName": "",
                                  "dateAdded": "2026-10-10"}], ["linux kernel"], 14, now)
        assert m2 == [], m2
        rh = ransomware_hits([{"group_name": "lockbit", "post_title": "example.com leak"}], ["example.com", "example.org"])
        assert rh == ["your domain example.com appears on a ransomware leak site (lockbit)"], rh
        assert xon_names({"breaches": [["Adobe", "LinkedIn"]]}) == ["Adobe", "LinkedIn"]
        assert xon_names({"Error": "Not found", "email": None}) == []
        print("threatintel.py self-check passed")
    else:
        print(json.dumps(gather(), indent=2))
