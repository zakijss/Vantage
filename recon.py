#!/usr/bin/env python3
"""Attack-surface checks for Vantage, over your own systems only.

External: what the internet sees of home. Your public IP looked up in Shodan's
InternetDB (keyless; the ports and known vulnerabilities its scanners have
seen, nothing probed from here), and the tailnet machine names that public
certificate-transparency logs reveal (every `tailscale cert` is logged).
This host: sockets listening beyond loopback and the tailnet, Serve routes and
Funnel, from a collector on the host that writes /state/exposure.json (Vantage
runs in a container and cannot see the host's sockets; README.md has the format).
Machines: the tailnet's devices, their key expiry and when they were last seen.
Domains: only those listed in recon_domains (none by default): DNS,
SPF/DMARC/DKIM, CT names, TLS expiry.

Nothing here touches a host that isn't yours, and nothing scans anything.

Stdlib only, to match the rest of Vantage. DNS goes over DNS-over-HTTPS
(dns.google), so no resolver library is needed.
"""
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import config

try:
    import store
except Exception:
    store = None

# Your domains. Apex names only; subdomains are discovered from CT.
DOMAINS = config.get("recon_domains", [], env="DASH_RECON_DOMAINS")
# The tailnet's DNS domain (example.ts.net), whose machine names CT logs reveal. Empty: skipped.
TAILNET = config.get("tailnet_domain", "", env="DASH_TAILNET_DOMAIN")
EXPOSURE = config.get("exposure_file", os.path.join(config.STATE_DIR, "exposure.json"), env="DASH_EXPOSURE")
# What this host is called in the findings.
HOST = (config.get("host") or {}).get("name") or "this host"
# Ports that listen beyond loopback on purpose; by default ssh and Tailscale's
# WireGuard port.
EXPECTED_OPEN = {str(p).strip() for p in config.get("expected_open", ["22", "41641"], env="DASH_EXPECTED_OPEN")}
# What a port usually is, so a flag says more than a number.
PORT_NAMES = {"22": "ssh", "80": "http", "443": "https", "7547": "TR-069, the ISP's remote management of the modem",
              "9090": "Cockpit", "6881": "BitTorrent", "45876": "Beszel agent",
              "41641": "Tailscale", "2049": "NFS", "20048": "NFS mountd", "3389": "RDP", "5432": "PostgreSQL", "8080": "http-alt"}
# What the internet may reach on the home IP (a torrent client's peer port, say). None by default.
EXPECTED_PUBLIC = {str(p).strip() for p in config.get("expected_public", [], env="DASH_EXPECTED_PUBLIC")}

_UA = {"User-Agent": "vantage-recon"}
_DOH = "https://dns.google/resolve"


def _get(url, timeout=8):
    req = urllib.request.Request(url, headers=_UA)
    with config.urlopen(req, timeout=timeout) as r:
        return r.read()


def dns(name, rrtype):
    """One DNS-over-HTTPS query. Returns a list of record strings (may be empty)."""
    try:
        q = urllib.parse.urlencode({"name": name, "type": rrtype})
        data = json.loads(_get(f"{_DOH}?{q}"))
        out = []
        for ans in data.get("Answer", []):
            v = ans.get("data", "")
            if rrtype == "TXT":
                v = v.strip('"').replace('" "', "")  # DoH quotes TXT chunks
            out.append(v)
        return out
    except Exception:
        return []


# Selectors to probe. Providers name their own: Google uses "google", Microsoft
# "selector1/2", Resend "resend"; the rest are common defaults.
DKIM_SELECTORS = ("google", "selector1", "selector2", "resend", "default", "k1", "s1", "s2", "mail", "dkim")


def email_auth(domain, mx=()):
    """The three records that stop others sending mail as you. Each: present? and the value.
    With the MX records given, a domain whose mail runs through Google must have
    Google's own key: a key for another sender (Resend, say) doesn't sign Gmail."""
    spf = next((t for t in dns(domain, "TXT") if t.lower().startswith("v=spf1")), None)
    dmarc_txt = dns(f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), None)
    found = [sel for sel in DKIM_SELECTORS
             if any("p=" in r for r in dns(f"{sel}._domainkey.{domain}", "TXT"))]
    dkim = found[0] if found else None
    google_mx = any("google.com" in m.lower() for m in mx)
    policy = ""
    if dmarc:
        for part in dmarc.split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:]
    # a weak or missing policy is the thing worth flagging
    warn = []
    if not spf:
        warn.append("no SPF")
    if not dmarc:
        warn.append("no DMARC")
    elif policy in ("", "none"):
        warn.append("DMARC p=none (monitor only)")
    if google_mx and "google" not in found:
        others = f"; signed only for {', '.join(found)}" if found else ""
        warn.append(f"Google mail is not DKIM-signed (no google._domainkey{others})")
    elif not found:
        warn.append("no DKIM on common selectors")
    return {"spf": spf, "dmarc": dmarc, "dmarc_policy": policy or None,
            "dkim_selector": dkim, "dkim_selectors": found, "warnings": warn}


def cert_names(domain, timeout=12):
    """Names under a domain seen in certificate transparency logs. crt.sh first,
    Cert Spotter (keyless) when crt.sh is down, which is often. None if neither answers."""
    names = set()
    try:
        q = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
        for row in json.loads(_get(f"https://crt.sh/?{q}", timeout=timeout) or b"[]"):
            names.update((row.get("name_value") or "").split("\n"))
    except Exception:
        try:
            q = urllib.parse.urlencode({"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
            for row in json.loads(_get(f"https://api.certspotter.com/v1/issuances?{q}", timeout=timeout)):
                names.update(row.get("dns_names") or [])
        except Exception:
            return None
    return sorted({n.strip().lower().lstrip("*.") for n in names
                   if n.strip().lower().endswith(domain) and "@" not in n})


def tls_expiry(host, port=443, timeout=6):
    """Days left on the certificate a host is actually serving."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                exp = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
        return round((exp - time.time()) / 86400, 1)
    except Exception:
        return None


def check_domain(domain):
    a = dns(domain, "A")
    aaaa = dns(domain, "AAAA")
    mx = dns(domain, "MX")
    ns = dns(domain, "NS")
    subs = cert_names(domain) or []
    return {
        "domain": domain,
        "a": a, "aaaa": aaaa, "mx": mx, "ns": ns,
        "email_auth": email_auth(domain, mx),
        "subdomains": subs,
        "subdomain_count": len(subs),
        "tls_days": tls_expiry(domain) if a else None,
    }


def external():
    """The home IP as the internet sees it, and tailnet names in public CT logs."""
    out = {"ip": None, "ports": [], "vulns": [], "hostnames": [], "error": None}
    try:
        out["ip"] = _get("https://api.ipify.org", timeout=8).decode().strip()
        try:
            db = json.loads(_get(f"https://internetdb.shodan.io/{out['ip']}", timeout=10))
        except urllib.error.HTTPError as e:
            if e.code != 404:            # 404: Shodan has seen nothing on this IP
                raise
            db = {}
        out.update(ports=sorted(db.get("ports") or []), vulns=sorted(db.get("vulns") or []),
                   hostnames=db.get("hostnames") or [])
    except Exception as e:
        out["error"] = type(e).__name__
    out["tailnet_names"] = cert_names(TAILNET) if TAILNET else []
    return out


def _days(iso, now):
    try:
        t = time.mktime(time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
        return (t - now) / 86400
    except (TypeError, ValueError):
        return None


def local_exposure(exp, now=None):
    """This host and the tailnet machines, from the host collector's file.
    Returns (host, machines, flags)."""
    now = now or time.time()
    flags = []
    host = {"listening": [], "funnel": None, "serve_routes": 0, "age": None}
    machines = []
    if exp:
        host["age"] = round(now - exp.get("generated", 0))
        # UDP sockets in Linux's ephemeral range (32768-60999) are client sockets,
        # mostly slirp4netns forwarding containers' DNS lookups, not services.
        # A real UDP service in that range is hidden too; list its port in
        # DASH_EXPECTED_OPEN and it shows again.
        def ephemeral(p, port):
            return p == "udp" and port.isdigit() and 32768 <= int(port) <= 60999 and port not in EXPECTED_OPEN
        host["listening"] = sorted({f"{p}/{port}" for p, _, port in exp.get("listening", []) if not ephemeral(p, port)},
                                   key=lambda x: (x.split("/")[0], int(x.split("/")[1]) if x.split("/")[1].isdigit() else 0))
        for x in host["listening"]:
            if x.split("/")[1] not in EXPECTED_OPEN:
                flags.append(f"{HOST} listens on {x} beyond loopback and the tailnet")
        host["funnel"] = bool(exp.get("funnel"))
        if host["funnel"]:
            flags.append(f"Tailscale Funnel is on: something on {HOST} is public")
        host["serve_routes"] = len(exp.get("serve") or {})
        # the collector runs hourly, so two hours means a run was missed
        if host["age"] > 2 * 3600:
            flags.append(f"the exposure data is {host['age'] // 60} minutes old (is the collector running?)")
        for d in exp.get("tailnet") or []:
            m = dict(d)
            exp_days = _days(d.get("key_expiry"), now)
            m["key_days"] = None if exp_days is None else round(exp_days)
            seen = _days(d.get("last_seen"), now)
            m["seen_days"] = None if d.get("online") or seen is None else round(-seen)
            if d.get("expired") or (exp_days is not None and exp_days < 0):
                flags.append(f"{d['name']}: its tailnet key has expired")
            elif exp_days is not None and exp_days < 14:
                flags.append(f"{d['name']}: its tailnet key expires in {round(exp_days)} days")
            if m["seen_days"] is not None and m["seen_days"] > 30:
                flags.append(f"{d['name']}: not seen on the tailnet for {m['seen_days']} days")
            machines.append(m)
    else:
        flags.append(f"no exposure data from {HOST} yet (is the collector running?)")
    return host, machines, flags


def attack_surface():
    """The slow, external half of the panel (every 6 h): the home IP, CT names
    for the tailnet, and any listed domains. Vantage adds the local half per request."""
    domains = []
    flags = []
    ext = external()
    for p in ext["ports"]:
        if str(p) not in EXPECTED_PUBLIC:
            what = PORT_NAMES.get(str(p))
            flags.append(f"the internet can reach port {p} on your home IP" + (f" ({what})" if what else "")
                         + ", seen by Shodan")
    if ext["vulns"]:
        flags.append(f"Shodan lists {len(ext['vulns'])} known vulnerabilities on your home IP: " + ", ".join(ext["vulns"][:5]))
    if store is not None and TAILNET and ext.get("tailnet_names"):
        base = store.get_json(f"ctbase:{TAILNET}")
        if base is None:
            store.set_json(f"ctbase:{TAILNET}", ext["tailnet_names"])
        else:
            fresh = [n for n in ext["tailnet_names"] if n not in set(base)]
            if fresh:
                flags.append("new tailnet name in public certificate logs: " + ", ".join(fresh[:5]))
                store.set_json(f"ctbase:{TAILNET}", sorted(set(base) | set(ext["tailnet_names"])))
    for d in DOMAINS:
        try:
            info = check_domain(d)
        except Exception as e:
            domains.append({"domain": d, "error": str(e)[:120]})
            continue
        domains.append(info)
        for w in info["email_auth"]["warnings"]:
            flags.append(f"{d}: {w}")
        if info["tls_days"] is not None and info["tls_days"] < 20:
            flags.append(f"{d}: TLS cert expires in {info['tls_days']} days")
        # certificate transparency: flag names that are new since the last run,
        # an early warning for a cert issued for your domain that you did not ask for
        if store is not None and info["subdomains"]:
            base = store.get_json(f"ctbase:{d}")
            if base is None:
                store.set_json(f"ctbase:{d}", info["subdomains"])  # seed quietly on first run
            else:
                fresh = [n for n in info["subdomains"] if n not in set(base)]
                if fresh:
                    flags.append(f"{d}: new certificate-transparency names: " + ", ".join(fresh[:5]))
                    store.set_json(f"ctbase:{d}", sorted(set(base) | set(info["subdomains"])))
    return {"generated": round(time.time()), "external": ext, "domains": domains, "flags": flags}


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        now = time.mktime(time.strptime("2026-10-12T12:00:00", "%Y-%m-%dT%H:%M:%S")) - time.timezone
        globals()["HOST"], globals()["EXPECTED_OPEN"] = "srv", {"22", "9090", "41641"}
        exp = {"generated": now - 60, "funnel": False, "serve": {"8080": "x"},
               "listening": [["tcp", "*", "9090"], ["tcp", "0.0.0.0", "22"], ["tcp", "*", "5432"],
                             ["udp", "0.0.0.0", "43282"], ["udp", "0.0.0.0", "41641"]],
               "tailnet": [{"name": "srv", "online": True, "self": True},
                           {"name": "phone", "online": False, "last_seen": "2026-08-01T00:00:00Z"},
                           {"name": "old", "online": True, "key_expiry": "2026-10-20T00:00:00Z"}]}
        host, machines, flags = local_exposure(exp, now)
        assert host["listening"] == ["tcp/22", "tcp/5432", "tcp/9090", "udp/41641"], host   # 43282: ephemeral
        assert "srv listens on tcp/5432 beyond loopback and the tailnet" in flags
        assert "phone: not seen on the tailnet for 72 days" in flags, flags
        assert "old: its tailnet key expires in 8 days" in flags, flags
        assert len(flags) == 3, flags
        assert local_exposure(None, now)[2] == ["no exposure data from srv yet (is the collector running?)"]
        assert not [f for f in local_exposure({**exp, "generated": now - 5400}, now)[2] if "minutes old" in f]
        assert any(f.startswith("the exposure data is 121 minutes old") for f in local_exposure({**exp, "generated": now - 7300}, now)[2])
        print("recon.py self-check passed")
    else:
        print(json.dumps(attack_surface(), indent=2))
