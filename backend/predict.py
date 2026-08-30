"""
predict.py
-----------
Loads the trained model bundle once and scores URLs. Uses
feature_extractor.extract_feature_vector() -- the exact same function
train.py used via preprocessing.py -- so ML inference features are always
identical to training features by construction. The trained model and
its features are UNCHANGED by anything in this file.

On top of the raw ML probability, this module now runs live verification
(domain existence, SSL, WHOIS, DNS, HTTP/redirects), brand-impersonation
(typosquat) detection, and optional threat-intel lookups, then hands
everything to decision_engine.combine() to produce the final verdict the
user actually sees. Live verification is ON by default -- a URL is no
longer judged on lexical structure alone.
"""

import os
from functools import lru_cache

from config import MODEL_BUNDLE_PATH, get_logger
from model_manager import load_bundle
from feature_extractor import extract_features, FEATURE_NAMES
from explainability import generate_reasons, shap_explanation
import security_checks
import brand_similarity
import threat_intel
import decision_engine

logger = get_logger("predict")


@lru_cache(maxsize=1)
def _get_bundle():
    if not os.path.exists(MODEL_BUNDLE_PATH):
        raise FileNotFoundError(
            f"No trained model found at {MODEL_BUNDLE_PATH}. Run `python train.py` first."
        )
    return load_bundle(MODEL_BUNDLE_PATH)


def predict_url(url: str, include_live_intel: bool = True, include_shap: bool = True) -> dict:
    """
    include_live_intel=True (the default): runs DNS/SSL/WHOIS/HTTP checks,
    typosquat detection, and threat-intel lookups, and folds them into the
    final verdict via decision_engine.combine(). Set to False only for a
    fast, structure-only ML score (e.g. bulk/offline scoring where network
    access isn't available) -- the response will clearly mark live checks
    as skipped rather than silently pretending they ran.
    """
    bundle = _get_bundle()
    model, scaler = bundle["model"], bundle["scaler"]

    feats = extract_features(url)
    vector = [feats[name] for name in FEATURE_NAMES]
    scaled = scaler.transform([vector])

    model_probability = float(model.predict_proba(scaled)[0][1])
    ml_reasons = generate_reasons(feats, model_probability)

    live_intel, brand_result, threat_result = None, None, None
    decision = None

    if include_live_intel:
        live_intel = security_checks.gather_live_intel(url)
        brand_result = brand_similarity.check_brand_similarity(url)
        threat_result = threat_intel.gather_threat_intel(url)
        decision = decision_engine.combine(model_probability, live_intel, brand_result, threat_result)
        final_score = decision["final_score"]
        risk_level = decision["risk_level"]
        reasons = ml_reasons + decision["reasons"]
    else:
        final_score = model_probability
        risk_level = decision_engine._bucket(final_score)
        reasons = ml_reasons + ["Live domain verification was skipped for this scan (structure-only score)."]

    verdict = "Phishing" if final_score >= 0.5 else "Legitimate"

    result = {
        "url": url,
        "verdict": verdict,
        "model_probability": round(model_probability, 4),
        "displayed_probability": round(final_score, 4),
        "final_score": round(final_score, 4),
        "risk_level": risk_level,
        "confidence": round(max(final_score, 1 - final_score), 4),
        "reasons": reasons,
        "raw_features": feats,
        "model_used": bundle["model_name"],
        "live_verification_performed": include_live_intel,
    }

    if decision is not None:
        result["decision_breakdown"] = decision["contributions"]
        result["ml_weight"] = decision["ml_weight"]
        result["live_weight"] = decision["live_weight"]

    if include_shap:
        result["feature_contributions"] = shap_explanation(
            model, scaler, FEATURE_NAMES, vector,
            global_importances=bundle.get("global_feature_importances"),
        )

    if live_intel is not None:
        result["live_intel"] = live_intel
    if brand_result is not None:
        result["brand_similarity"] = brand_result
    if threat_result is not None:
        result["threat_intel"] = threat_result

    return result


if __name__ == "__main__":
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://jask.powerforxes.shop/yuop/malware.exe"
    import json
    print(json.dumps(predict_url(test_url), indent=2, default=str))
