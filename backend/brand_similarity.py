"""
brand_similarity.py
---------------------
Typosquatting / brand-impersonation detection.

Uses rapidfuzz if it's installed (fast, C-accelerated), otherwise falls
back to a small pure-python Levenshtein implementation below -- so this
module never hard-fails for lack of a dependency, in this sandbox or
anywhere else.

This is intentionally a STATIC, curated list of well-known brand domains
commonly targeted by phishing (banks, payment platforms, big tech, email
providers, shipping). It is meant to catch "close-but-not-quite" domains
like `netf1ix.com` or `paypa1-secure.com` -- not to be an exhaustive
trademark database.
"""

import re
from urllib.parse import urlparse

from config import get_logger

logger = get_logger("brand_similarity")

try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except ImportError:
    HAS_RAPIDFUZZ = False


WELL_KNOWN_BRANDS = [
    "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
    "whatsapp.com", "amazon.com", "microsoft.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "netflix.com", "paypal.com", "linkedin.com",
    "twitter.com", "x.com", "yahoo.com", "ebay.com", "dropbox.com",
    "adobe.com", "github.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "americanexpress.com", "citibank.com", "hdfcbank.com", "icicibank.com",
    "sbi.co.in", "paytm.com", "phonepe.com", "flipkart.com", "steamcommunity.com",
    "steampowered.com", "spotify.com", "twitch.tv", "discord.com", "coinbase.com",
    "binance.com", "wellsfargo.com", "usps.com", "fedex.com", "dhl.com",
    "irs.gov",
]


def _levenshtein(a: str, b: str) -> int:
    """Pure-python Levenshtein distance -- zero external dependencies."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev_row = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur_row = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur_row[j] = min(
                prev_row[j] + 1,        # deletion
                cur_row[j - 1] + 1,     # insertion
                prev_row[j - 1] + cost  # substitution
            )
        prev_row = cur_row
    return prev_row[lb]


def _similarity_ratio(a: str, b: str) -> float:
    """0-100 similarity score, higher = more similar."""
    if HAS_RAPIDFUZZ:
        return fuzz.ratio(a, b)
    dist = _levenshtein(a, b)
    max_len = max(len(a), len(b)) or 1
    return round((1 - dist / max_len) * 100, 2)


LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
})


def _normalize_leet(s: str) -> str:
    return s.translate(LEET_MAP)


def _best_similarity(token: str, brand_sld: str) -> float:
    """Highest of: raw similarity, and similarity after normalizing common
    leetspeak/digit substitutions (0->o, 1->l, 3->e, 4->a, 5->s, 7->t, ...).
    This is what reliably catches things like g00gle -> google or
    netf1ix -> netflix, which raw edit-distance alone can under-score
    once the ".com" suffix is stripped out for the SLD-only comparison."""
    raw = _similarity_ratio(token, brand_sld)
    normalized = _similarity_ratio(_normalize_leet(token), brand_sld)
    return max(raw, normalized)


def extract_registrable_domain(url: str) -> str:
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _sld(domain: str) -> str:
    """Second-level label without the TLD, e.g. 'amazon.com' -> 'amazon'."""
    parts = domain.split(".")
    return parts[0] if parts else domain


BRAND_SLDS = sorted({_sld(b) for b in WELL_KNOWN_BRANDS})


def check_brand_similarity(url: str, threshold: float = 80.0) -> dict:
    """
    Returns the closest well-known brand to this URL's domain and how
    similar it is. Compares the full domain, the SLD alone, and each
    hyphen/digit-delimited token of the SLD against every known brand SLD
    -- this is what catches patterns like `amaz0n-login.com` or
    `netf1ix.com`, not just a whole-domain match. A high similarity to a
    brand that is NOT the exact same domain is a strong typosquatting
    signal.
    """
    domain = extract_registrable_domain(url)
    if not domain:
        return {"available": True, "is_impersonation_suspected": False, "closest_brand": None, "similarity": 0.0}

    if domain in WELL_KNOWN_BRANDS:
        return {
            "available": True,
            "domain": domain,
            "is_impersonation_suspected": False,
            "closest_brand": domain,
            "similarity": 100.0,
            "note": "This IS the legitimate brand domain.",
        }

    sld = _sld(domain)
    candidate_tokens = {sld} | {t for t in re.split(r"[-_.]", sld) if len(t) >= 4}

    best_brand, best_score = None, 0.0
    for brand_sld in BRAND_SLDS:
        for token in candidate_tokens:
            score = _best_similarity(token, brand_sld)
            if score > best_score:
                best_brand, best_score = brand_sld, score

    best_brand_domain = next((b for b in WELL_KNOWN_BRANDS if _sld(b) == best_brand), best_brand)
    is_suspected = best_score >= threshold and domain != best_brand_domain

    return {
        "available": True,
        "domain": domain,
        "closest_brand": best_brand_domain,
        "similarity": round(best_score, 2),
        "is_impersonation_suspected": is_suspected,
    }


if __name__ == "__main__":
    for u in ["https://netf1ix.com", "https://nevbhjtflix.com", "https://paypa1.com",
              "https://micr0soft.com", "https://amaz0n-login.com", "https://g00gle.com",
              "https://google.com", "https://en.wikipedia.org"]:
        print(u, "->", check_brand_similarity(u))
