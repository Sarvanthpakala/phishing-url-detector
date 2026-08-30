"""
decision_engine.py
--------------------
Combines everything into ONE final verdict:
    - ML model probability      (from the trained, unmodified classifier)
    - Domain existence / DNS
    - SSL certificate validity
    - WHOIS registration age
    - HTTP / redirect behaviour
    - Brand-impersonation (typosquat) similarity
    - Threat intelligence (when a provider is configured)

Design: this is a transparent, weighted rule engine layered on top of the
ML score -- not a second black box. Every contribution below is a plain
number you can read straight out of RULE_WEIGHTS, and the final breakdown
returned to the caller lists exactly which rules fired and by how much,
so the UI can show "why" in plain English instead of just a percentage.

IMPORTANT: this module does NOT touch the trained model, the training
pipeline, or the dataset. It only combines the model's output with live
signals gathered elsewhere (security_checks.py, brand_similarity.py,
threat_intel.py) after the fact.
"""

from config import get_logger

logger = get_logger("decision_engine")

# How much weight the raw ML probability gets vs. the live-verification
# rule score. Kept below 1.0 for ML on purpose -- the whole point of this
# revision is that structure-only ML predictions can no longer solely
# decide the verdict.
ML_WEIGHT = 0.55
LIVE_WEIGHT = 0.45

# Each rule below adds this much to the 0-1 "live risk" component when it
# fires. They are additive and then capped at 1.0 -- multiple weak signals
# can add up to a strong one, which is the intended behaviour.
RULE_WEIGHTS = {
    "domain_does_not_resolve": 0.55,
    "dns_no_records_at_all": 0.20,
    "ssl_missing_on_https_capable_domain": 0.20,
    "ssl_invalid_or_untrusted": 0.20,
    "ssl_expired": 0.15,
    "ssl_self_signed": 0.15,
    "ssl_hostname_mismatch": 0.15,
    "ssl_recently_issued": 0.08,
    "whois_recently_registered": 0.20,
    "whois_unavailable": 0.04,
    "http_does_not_respond": 0.12,
    "http_suspicious_redirect_chain": 0.12,
    "http_downgrades_to_http": 0.07,
    "brand_impersonation_suspected": 0.35,
}

# Hard floors: some signals are strong enough that, when triggered, the
# final score should never read as "safe" even if the ML model and every
# other check disagree -- these are ground-truth-adjacent situations.
FLOOR_ON_THREAT_INTEL_HIT = 0.97
FLOOR_ON_DOMAIN_NOT_RESOLVING = 0.85
FLOOR_ON_BRAND_IMPERSONATION = 0.70


def _bucket(score: float) -> str:
    if score >= 0.85:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.3:
        return "Medium"
    return "Low"


def combine(
    model_probability: float,
    live_intel: dict,
    brand_result: dict = None,
    threat_result: dict = None,
) -> dict:
    """Returns {final_score, risk_level, live_risk_component, contributions, reasons}."""
    brand_result = brand_result or {}
    threat_result = threat_result or {}
    contributions = []  # list of {rule, weight, detail}
    reasons = []

    domain = live_intel.get("domain", {}) or {}
    ssl_info = live_intel.get("ssl", {}) or {}
    dns_info = live_intel.get("dns", {}) or {}
    whois_info = live_intel.get("whois", {}) or {}
    http_info = live_intel.get("http", {}) or {}

    def fire(rule_key, detail):
        w = RULE_WEIGHTS[rule_key]
        contributions.append({"rule": rule_key, "weight": w, "detail": detail})
        reasons.append(detail)
        return w

    live_risk = 0.0

    if domain.get("available") and domain.get("exists") is False:
        live_risk += fire("domain_does_not_resolve", "Domain does not resolve via DNS -- it may not exist or is no longer registered")
    elif dns_info.get("available") and dns_info.get("resolves") is False:
        live_risk += fire("dns_no_records_at_all", "No usable DNS records (A/CNAME) found for this domain")

    if ssl_info.get("available"):
        if ssl_info.get("exists") is False:
            live_risk += fire("ssl_missing_on_https_capable_domain", "No SSL certificate could be retrieved for this domain")
        else:
            if ssl_info.get("valid") is False:
                live_risk += fire("ssl_invalid_or_untrusted", "SSL certificate is invalid or not trusted")
            if ssl_info.get("is_expired"):
                live_risk += fire("ssl_expired", "SSL certificate has expired")
            if ssl_info.get("is_self_signed"):
                live_risk += fire("ssl_self_signed", "SSL certificate appears to be self-signed")
            if ssl_info.get("hostname_matches_certificate") is False:
                live_risk += fire("ssl_hostname_mismatch", "SSL certificate does not match the requested hostname")
            if ssl_info.get("is_recently_issued"):
                live_risk += fire("ssl_recently_issued", "SSL certificate was issued very recently")

    if whois_info.get("available"):
        if whois_info.get("is_recently_registered"):
            live_risk += fire("whois_recently_registered", "Domain was registered very recently")
    elif whois_info.get("error") and whois_info.get("error") != "python-whois not installed":
        live_risk += fire("whois_unavailable", "WHOIS registration data could not be retrieved")

    if http_info.get("available"):
        if http_info.get("responds") is False:
            live_risk += fire("http_does_not_respond", "The site did not respond to an HTTP request")
        else:
            if http_info.get("suspicious_redirect"):
                live_risk += fire("http_suspicious_redirect_chain", "URL goes through an unusually long redirect chain")
            if http_info.get("downgrades_to_http"):
                live_risk += fire("http_downgrades_to_http", "Connection downgrades from HTTPS back to plain HTTP")

    if brand_result.get("is_impersonation_suspected"):
        live_risk += fire(
            "brand_impersonation_suspected",
            f"Domain closely resembles '{brand_result.get('closest_brand')}' ({brand_result.get('similarity')}% similar) but is not that domain",
        )

    live_risk = min(live_risk, 1.0)

    final_score = (ML_WEIGHT * model_probability) + (LIVE_WEIGHT * live_risk)

    # Hard floors for near-certain situations
    floor_reason = None
    if threat_result.get("is_flagged_malicious"):
        final_score = max(final_score, FLOOR_ON_THREAT_INTEL_HIT)
        floor_reason = "Flagged as malicious by an external threat-intelligence provider"
    elif domain.get("available") and domain.get("exists") is False:
        final_score = max(final_score, FLOOR_ON_DOMAIN_NOT_RESOLVING)
    elif brand_result.get("is_impersonation_suspected"):
        final_score = max(final_score, FLOOR_ON_BRAND_IMPERSONATION)

    if floor_reason:
        reasons.insert(0, floor_reason)

    final_score = round(min(max(final_score, 0.0), 1.0), 4)

    return {
        "final_score": final_score,
        "risk_level": _bucket(final_score),
        "model_probability": round(model_probability, 4),
        "live_risk_component": round(live_risk, 4),
        "ml_weight": ML_WEIGHT,
        "live_weight": LIVE_WEIGHT,
        "contributions": contributions,
        "reasons": reasons,
    }
