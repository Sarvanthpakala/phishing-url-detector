"""
explainability.py
-------------------
Turns a feature dict + model probability into:
    1. A risk score bucket (Low / Medium / High / Critical)
    2. A list of plain-English reasons (rule-based, always available)
    3. A SHAP-based per-feature contribution list, when the `shap` package
       is installed and the underlying model supports it. Falls back to
       the model's built-in feature_importances_ / coefficients otherwise.
"""

import numpy as np
from config import get_logger

logger = get_logger("explainability")

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False


def risk_bucket(probability: float) -> str:
    if probability >= 0.85:
        return "Critical"
    if probability >= 0.6:
        return "High"
    if probability >= 0.3:
        return "Medium"
    return "Low"


def generate_reasons(feats: dict, probability: float) -> list:
    """Rule-based, human-readable reasons derived directly from the same
    feature values the model was trained on -- always available, no
    extra dependency required."""
    reasons = []

    if feats.get("entropy", 0) > 4.3:
        reasons.append("URL has unusually high character entropy (looks randomly generated)")
    if feats.get("has_ip_address"):
        reasons.append("Hostname is a raw IP address instead of a domain name")
    if feats.get("suspicious_keyword_count", 0) > 0:
        reasons.append("Contains keywords commonly used in phishing (e.g. login, verify, secure, account)")
    if feats.get("subdomain_count", 0) >= 3:
        reasons.append("Unusually deep subdomain chain")
    if feats.get("has_executable_extension"):
        reasons.append("Links directly to an executable/script file")
    if feats.get("is_shortened_url"):
        reasons.append("Uses a URL-shortening service, which can hide the real destination")
    if feats.get("has_suspicious_tld"):
        reasons.append("Uses a top-level domain frequently abused for phishing/spam")
    if not feats.get("has_https"):
        reasons.append("Connection is not served over HTTPS")
    if feats.get("has_homoglyph_digit"):
        reasons.append("Hostname mixes digits that visually resemble letters (possible homoglyph trick)")
    if feats.get("hostname_hyphen_count", 0) >= 2:
        reasons.append("Domain name contains multiple hyphens, a common brand-impersonation pattern")
    if feats.get("encoded_char_count", 0) > 2:
        reasons.append("URL contains several percent-encoded characters, which can obscure its true content")
    if feats.get("at_symbol_count", 0) > 0:
        reasons.append("Contains an '@' symbol, which can be used to disguise the real destination host")
    if feats.get("abnormal_hostname_length"):
        reasons.append("Hostname is unusually long")

    if not reasons:
        if probability < 0.3:
            reasons.append("No notable suspicious lexical or structural patterns detected")
        else:
            reasons.append("Model flagged subtle structural patterns not captured by the rule set above (see SHAP breakdown)")

    return reasons


def shap_explanation(model, scaler, feature_names, feature_vector, global_importances: dict = None):
    """Returns a list of {feature, value, contribution} sorted by |contribution|.
    Falls back to feature_importances_/coef_ if SHAP isn't installed or the
    model type isn't supported by the fast TreeExplainer path."""
    scaled = scaler.transform([feature_vector])

    if HAS_SHAP:
        try:
            explainer = shap.Explainer(model, feature_names=feature_names)
            sv = explainer(scaled)
            values = sv.values[0]
            if values.ndim > 1:  # some explainers return per-class
                values = values[:, -1]
            contributions = sorted(
                zip(feature_names, feature_vector, values),
                key=lambda x: abs(x[2]),
                reverse=True,
            )
            return [
                {"feature": f, "value": v, "contribution": round(float(c), 4)}
                for f, v, c in contributions[:10]
            ]
        except Exception as e:
            logger.warning(f"SHAP explanation failed, falling back to model importances: {e}")

    # Fallback: static feature importance x (scaled value) as a proxy contribution
    importances = None
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        importances = model.coef_[0]
    elif global_importances:
        importances = np.array([global_importances.get(f, 0.0) for f in feature_names])

    if importances is None:
        return []

    contributions = sorted(
        zip(feature_names, feature_vector, importances * scaled[0]),
        key=lambda x: abs(x[2]),
        reverse=True,
    )
    return [
        {"feature": f, "value": v, "contribution": round(float(c), 4)}
        for f, v, c in contributions[:10]
    ]
