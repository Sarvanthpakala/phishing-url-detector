"""
security_checks.py
--------------------
Live, network-dependent intelligence about a URL: domain existence, SSL
certificate, DNS records, WHOIS registration, HTTP/redirect behaviour.

These are DISPLAY / EXPLANATION signals (see the design note at the top
of feature_extractor.py for why they are not fed into the trained model
directly) -- but as of this revision they ARE fed into decision_engine.py,
which combines them with the ML probability into the final adjusted score
the user actually sees. Every function here fails soft: if there is no
internet connectivity, DNS is blocked, or a library is missing, it
returns a dict with "available": False instead of raising, so the rest of
the app keeps working.
"""

import socket
import ssl
import datetime
from urllib.parse import urlparse

from config import get_logger

logger = get_logger("security_checks")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import whois  # python-whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver  # dnspython
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def check_domain_exists(hostname: str, timeout: float = 4.0) -> dict:
    """Cheapest, fastest possible existence check -- plain DNS resolution.
    Used as the first gate: if a domain doesn't resolve at all, everything
    downstream (SSL, HTTP) is going to fail too, and that alone is a very
    strong phishing signal (freshly-thrown-away or never-registered domain)."""
    result = {"available": True, "exists": False}
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        result["exists"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ssl_certificate(hostname: str, timeout: float = 4.0) -> dict:
    result = {"available": False, "exists": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        san_list = [v for k, v in cert.get("subjectAltName", []) if k.lower() == "dns"]
        hostname_matches = hostname.lower() in [s.lower().lstrip("*.") for s in san_list] or \
            hostname.lower() == subject.get("commonName", "").lower()
        age_days = (datetime.datetime.utcnow() - not_before).days
        is_self_signed = issuer.get("organizationName") == subject.get("organizationName") and \
            issuer.get("commonName") == subject.get("commonName")
        result.update({
            "available": True,
            "exists": True,
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "subject": subject.get("commonName", hostname),
            "issued_on": not_before.isoformat(),
            "expires_on": not_after.isoformat(),
            "certificate_age_days": age_days,
            "is_recently_issued": age_days < 30,
            "is_expired": not_after < datetime.datetime.utcnow(),
            "hostname_matches_certificate": hostname_matches,
            "is_self_signed": is_self_signed,
        })
    except ssl.SSLCertVerificationError as e:
        result.update({"available": True, "exists": True, "valid": False, "error": str(e)})
    except Exception as e:
        result["error"] = str(e)
    return result


def check_dns(hostname: str, timeout: float = 4.0) -> dict:
    result = {"available": False}
    try:
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            a_records, mx_records, txt_records, ns_records, cname_records = [], [], [], [], []
            for rtype, bucket in (("A", a_records), ("MX", mx_records), ("TXT", txt_records),
                                   ("NS", ns_records), ("CNAME", cname_records)):
                try:
                    bucket.extend(r.to_text() for r in resolver.resolve(hostname, rtype))
                except Exception:
                    pass
            result.update({
                "available": True,
                "resolves": len(a_records) > 0 or len(cname_records) > 0,
                "a_records": a_records,
                "mx_records": mx_records,
                "txt_records": txt_records,
                "nameservers": ns_records,
                "cname_records": cname_records,
            })
        else:
            ip = socket.gethostbyname(hostname)
            result.update({
                "available": True, "resolves": True, "a_records": [ip],
                "mx_records": [], "txt_records": [], "nameservers": [], "cname_records": [],
            })
    except Exception as e:
        result["resolves"] = False
        result["error"] = str(e)
        result["available"] = True
    return result


def check_whois(hostname: str) -> dict:
    result = {"available": False}
    if not HAS_WHOIS:
        result["error"] = "python-whois not installed"
        return result
    try:
        w = whois.whois(hostname)

        def _first(v):
            return v[0] if isinstance(v, list) else v

        creation = _first(w.creation_date)
        expiration = _first(w.expiration_date)
        updated = _first(getattr(w, "updated_date", None))
        country = getattr(w, "country", None)
        country = _first(country) if country else None
        age_days = (datetime.datetime.utcnow() - creation).days if creation else None

        result.update({
            "available": True,
            "registrar": w.registrar,
            "creation_date": creation.isoformat() if creation else None,
            "expiration_date": expiration.isoformat() if expiration else None,
            "last_updated": updated.isoformat() if updated else None,
            "registrant_country": country,
            "domain_age_days": age_days,
            "is_recently_registered": (age_days is not None and age_days < 90),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def check_http(url: str, timeout: float = 6.0) -> dict:
    """Unified HTTP/HTTPS + redirect check: does the site respond, what's
    the status code, does it redirect through a suspicious chain, and is
    HTTPS actually enforced (e.g. an http:// URL that never upgrades)."""
    result = {"available": False}
    if not HAS_REQUESTS:
        result["error"] = "requests not installed"
        return result
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        chain = [r.url for r in resp.history] + [resp.url]
        schemes_seen = {urlparse(u).scheme for u in chain}
        ends_on_https = urlparse(resp.url).scheme == "https"
        result.update({
            "available": True,
            "responds": True,
            "status_code": resp.status_code,
            "redirect_count": len(resp.history),
            "redirect_chain": chain,
            "final_url": resp.url,
            "suspicious_redirect": len(resp.history) >= 3,
            "https_enforced": ends_on_https,
            "downgrades_to_http": "https" in schemes_seen and not ends_on_https,
        })
    except Exception as e:
        result["responds"] = False
        result["error"] = str(e)
        result["available"] = True
    return result


def gather_live_intel(url: str) -> dict:
    """Best-effort collection of every live signal. Never raises."""
    hostname = urlparse(url if "://" in url else "http://" + url).hostname or ""
    intel = {"hostname": hostname}
    try:
        intel["domain"] = check_domain_exists(hostname)
    except Exception as e:
        intel["domain"] = {"available": False, "error": str(e)}
    try:
        intel["ssl"] = check_ssl_certificate(hostname)
    except Exception as e:
        intel["ssl"] = {"available": False, "error": str(e)}
    try:
        intel["dns"] = check_dns(hostname)
    except Exception as e:
        intel["dns"] = {"available": False, "error": str(e)}
    try:
        intel["whois"] = check_whois(hostname)
    except Exception as e:
        intel["whois"] = {"available": False, "error": str(e)}
    try:
        intel["http"] = check_http(url)
    except Exception as e:
        intel["http"] = {"available": False, "error": str(e)}
    return intel
