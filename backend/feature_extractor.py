"""
feature_extractor.py
---------------------
THE single feature extraction module. train.py, predict.py and app.py all
import extract_feature_vector() from here and nowhere else. There is no
second copy of this logic anywhere in the project -- that is what
guarantees training and inference can never see different features.

Design decision (read this before changing the feature set):
    Only features that can be computed *offline*, deterministically, from
    the URL string alone are used to train the ML model. Live signals
    (SSL certificate details, DNS records, WHOIS age, redirect chains --
    see security_checks.py) depend on network access and the current
    state of the internet, which is neither reproducible for training nor
    guaranteed to be available at prediction time. Feeding the model a
    feature that is sometimes missing would silently change its input
    distribution between training and serving. So:

        - STATIC features (this file)       -> fed into the ML classifier
        - LIVE / OSINT features (security_checks.py) -> shown to the user
          as supporting evidence and folded into the *displayed* risk
          score via a transparent rule-based booster, never into the
          classifier's input vector.

    This keeps "training features == inference features" true by
    construction, while still satisfying the requirement to surface
    SSL/DNS/WHOIS/redirect information in the UI.
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter

# Ordered list of feature names. This exact order is what gets saved
# alongside the trained model (see model_manager.py) and is enforced
# every time a vector is built, in training or in prediction.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "token_count",
    "entropy",
    "digit_ratio",
    "alpha_ratio",
    "special_char_ratio",
    "uppercase_ratio",
    "max_repeated_char_run",
    "subdomain_count",
    "slash_count",
    "dash_count",
    "underscore_count",
    "at_symbol_count",
    "equals_count",
    "ampersand_count",
    "dot_count",
    "digit_count_in_domain",
    "suspicious_keyword_count",
    "has_ip_address",
    "is_shortened_url",
    "has_executable_extension",
    "has_unicode_chars",
    "has_homoglyph_digit",
    "has_suspicious_tld",
    "has_https",
    "param_count",
    "nested_dir_count",
    "encoded_char_count",
    "abnormal_hostname_length",
    "hostname_hyphen_count",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "update", "secure",
    "account", "banking", "confirm", "password", "wallet", "invoice", "billing",
    "suspend", "unlock", "alert", "urgent", "click", "webscr", "ebayisapi",
    "paypal", "reset", "authenticate", "gift", "bonus", "free", "prize",
]

EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".dll", ".vbs", ".ps1", ".sh")

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st", "bl.ink", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".click", ".work", ".loan", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".shop", ".rest", ".fit", ".men", ".date", ".stream",
    ".icu", ".surf", ".cam", ".bid",
}

IP_REGEX = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

# Digits that visually resemble letters (a very small, well-known homoglyph set)
HOMOGLYPH_DIGITS = set("013457")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _max_repeated_run(s: str) -> int:
    if not s:
        return 0
    best = cur = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
    return best


def _safe_parse(url: str):
    url = (url or "").strip()
    if "://" not in url:
        url = "http://" + url
    try:
        return urlparse(url)
    except Exception:
        return urlparse("http://invalid-url.local")


def extract_features(url: str) -> dict:
    """Returns an ordered dict of {feature_name: value} for a single URL."""
    parsed = _safe_parse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full = url or ""
    domain_parts = hostname.split(".") if hostname else []

    total_len = len(full)
    alpha = sum(c.isalpha() for c in full)
    digits = sum(c.isdigit() for c in full)
    upper = sum(c.isupper() for c in full)
    special = sum(not c.isalnum() for c in full)

    is_ip = bool(hostname and IP_REGEX.match(hostname.split(":")[0]))

    # subdomain count: everything before the registrable domain, roughly
    # (e.g. a.b.example.com -> 2 subdomains). Good enough without a public
    # suffix list, and never depends on network access.
    subdomain_count = max(len(domain_parts) - 2, 0) if len(domain_parts) > 2 else 0

    lowered = full.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered)

    is_shortened = hostname in SHORTENER_DOMAINS
    has_exec_ext = path.lower().endswith(EXECUTABLE_EXTENSIONS)
    has_unicode = any(ord(c) > 127 for c in full)
    homoglyph_hits = sum(1 for c in hostname if c in HOMOGLYPH_DIGITS)

    tld = "." + domain_parts[-1] if domain_parts else ""
    suspicious_tld = tld in SUSPICIOUS_TLDS

    nested_dirs = max(path.count("/") - 1, 0)
    encoded_chars = full.count("%")

    feats = {
        "url_length": total_len,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "token_count": len(re.split(r"[\/\-\_\.\?\=\&]", full.strip("/"))) if full else 0,
        "entropy": round(_shannon_entropy(full), 4),
        "digit_ratio": round(digits / total_len, 4) if total_len else 0.0,
        "alpha_ratio": round(alpha / total_len, 4) if total_len else 0.0,
        "special_char_ratio": round(special / total_len, 4) if total_len else 0.0,
        "uppercase_ratio": round(upper / total_len, 4) if total_len else 0.0,
        "max_repeated_char_run": _max_repeated_run(full),
        "subdomain_count": subdomain_count,
        "slash_count": full.count("/"),
        "dash_count": full.count("-"),
        "underscore_count": full.count("_"),
        "at_symbol_count": full.count("@"),
        "equals_count": full.count("="),
        "ampersand_count": full.count("&"),
        "dot_count": full.count("."),
        "digit_count_in_domain": sum(c.isdigit() for c in hostname),
        "suspicious_keyword_count": keyword_hits,
        "has_ip_address": int(is_ip),
        "is_shortened_url": int(is_shortened),
        "has_executable_extension": int(has_exec_ext),
        "has_unicode_chars": int(has_unicode),
        "has_homoglyph_digit": int(homoglyph_hits > 0),
        "has_suspicious_tld": int(suspicious_tld),
        "has_https": int(parsed.scheme == "https"),
        "param_count": query.count("=") if query else 0,
        "nested_dir_count": nested_dirs,
        "encoded_char_count": encoded_chars,
        "abnormal_hostname_length": int(len(hostname) > 40),
        "hostname_hyphen_count": hostname.count("-"),
    }
    return feats


def extract_feature_vector(url: str) -> list:
    """Returns values in the fixed FEATURE_NAMES order -- what actually goes into the model."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


def explain_raw_signals(url: str) -> dict:
    """Human-readable version of the same features, used by explainability.py."""
    return extract_features(url)


if __name__ == "__main__":
    for test_url in [
        "https://www.google.com/search?q=test",
        "http://jask.powerforxes.shop/yuop/66cf56ae6e345_ColeusesWalkathon.exe",
        "http://120.61.239.166:45010/bin.sh",
    ]:
        print(test_url)
        print(extract_features(test_url))
        print()
