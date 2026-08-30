"""
threat_intel.py
-----------------
Pluggable threat-intelligence layer. Each provider is its own small
function that:
    - reads its API key from an environment variable (never hardcoded)
    - returns {"available": False, "configured": False} if no key is set
    - fails soft (never raises) on network/API errors

To add a real key later: set the environment variable and nothing else in
this codebase needs to change -- `gather_threat_intel()` picks it up
automatically next time it runs.

Currently wired up:
    - Google Safe Browsing  (GOOGLE_SAFE_BROWSING_API_KEY)
    - VirusTotal            (VIRUSTOTAL_API_KEY)
    - PhishTank             (no key required for basic lookups, but the
                              public API is rate-limited and can be slow --
                              disabled by default, toggle PHISHTANK_ENABLED=1)
    - OpenPhish             (community feed URL list -- no key required,
                              disabled by default, toggle OPENPHISH_ENABLED=1,
                              since it requires downloading + caching a feed)

Adding a new provider: write a `_check_<provider>(url) -> dict` function
with the same {available, configured, ...} shape and add it to PROVIDERS.
"""

import os
import base64

from config import get_logger

logger = get_logger("threat_intel")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def _check_google_safe_browsing(url: str) -> dict:
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "configured": False, "provider": "Google Safe Browsing"}
    if not HAS_REQUESTS:
        return {"available": False, "configured": True, "error": "requests not installed", "provider": "Google Safe Browsing"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=body, timeout=5)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        return {
            "available": True, "configured": True, "provider": "Google Safe Browsing",
            "is_malicious": len(matches) > 0, "threat_types": [m.get("threatType") for m in matches],
        }
    except Exception as e:
        return {"available": False, "configured": True, "error": str(e), "provider": "Google Safe Browsing"}


def _check_virustotal(url: str) -> dict:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "configured": False, "provider": "VirusTotal"}
    if not HAS_REQUESTS:
        return {"available": False, "configured": True, "error": "requests not installed", "provider": "VirusTotal"}

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key}, timeout=6,
        )
        if resp.status_code == 404:
            return {"available": True, "configured": True, "provider": "VirusTotal", "is_malicious": False, "note": "URL not previously analyzed"}
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return {
            "available": True, "configured": True, "provider": "VirusTotal",
            "is_malicious": malicious > 0, "engine_stats": stats,
        }
    except Exception as e:
        return {"available": False, "configured": True, "error": str(e), "provider": "VirusTotal"}


def _check_phishtank(url: str) -> dict:
    if os.environ.get("PHISHTANK_ENABLED", "0") != "1":
        return {"available": False, "configured": False, "provider": "PhishTank"}
    if not HAS_REQUESTS:
        return {"available": False, "configured": True, "error": "requests not installed", "provider": "PhishTank"}
    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"}, timeout=6,
        )
        resp.raise_for_status()
        results = resp.json().get("results", {})
        return {
            "available": True, "configured": True, "provider": "PhishTank",
            "is_malicious": bool(results.get("in_database") and results.get("valid")),
        }
    except Exception as e:
        return {"available": False, "configured": True, "error": str(e), "provider": "PhishTank"}


def _check_openphish(url: str) -> dict:
    if os.environ.get("OPENPHISH_ENABLED", "0") != "1":
        return {"available": False, "configured": False, "provider": "OpenPhish"}
    if not HAS_REQUESTS:
        return {"available": False, "configured": True, "error": "requests not installed", "provider": "OpenPhish"}
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=8)
        resp.raise_for_status()
        feed = set(resp.text.splitlines())
        return {"available": True, "configured": True, "provider": "OpenPhish", "is_malicious": url.strip() in feed}
    except Exception as e:
        return {"available": False, "configured": True, "error": str(e), "provider": "OpenPhish"}


PROVIDERS = [
    _check_google_safe_browsing,
    _check_virustotal,
    _check_phishtank,
    _check_openphish,
]


def gather_threat_intel(url: str) -> dict:
    """Runs every configured provider. Never raises. Returns a summary plus
    per-provider detail, so the UI can show 'not configured' honestly
    instead of pretending a check ran when it didn't."""
    results = []
    for provider_fn in PROVIDERS:
        try:
            results.append(provider_fn(url))
        except Exception as e:
            results.append({"available": False, "configured": False, "error": str(e), "provider": provider_fn.__name__})

    any_configured = any(r.get("configured") for r in results)
    any_malicious = any(r.get("is_malicious") for r in results if r.get("available"))

    return {
        "any_provider_configured": any_configured,
        "is_flagged_malicious": any_malicious,
        "providers": results,
    }
