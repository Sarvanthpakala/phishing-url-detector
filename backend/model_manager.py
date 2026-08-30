"""
model_manager.py
------------------
Builds the dictionary of candidate models and handles saving/loading the
final "model bundle" (best model + scaler + feature names + metadata) as
a single joblib file so predict.py and app.py only ever load one artifact.
"""

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    AdaBoostClassifier,
    HistGradientBoostingClassifier,
)

from config import RANDOM_STATE, get_logger

logger = get_logger("model_manager")


def get_candidate_models() -> dict:
    """Every model that is actually usable on this machine right now.
    Optional libraries (xgboost/lightgbm/catboost) are added only if
    installed -- nothing else in the pipeline needs to know which ones
    were available."""
    models = {
        "LogisticRegression": LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300, max_depth=None, class_weight="balanced",
            n_jobs=-1, random_state=RANDOM_STATE
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=300, class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE
        ),
        "GradientBoosting": GradientBoostingClassifier(random_state=RANDOM_STATE),
        "AdaBoost": AdaBoostClassifier(random_state=RANDOM_STATE),
        "HistGradientBoosting": HistGradientBoostingClassifier(random_state=RANDOM_STATE),
    }

    try:
        from xgboost import XGBClassifier
        models["XGBoost"] = XGBClassifier(
            n_estimators=300, max_depth=6, use_label_encoder=False,
            eval_metric="logloss", random_state=RANDOM_STATE, n_jobs=-1,
        )
    except ImportError:
        logger.warning("xgboost not installed -- skipping (pip install xgboost to enable).")

    try:
        from lightgbm import LGBMClassifier
        models["LightGBM"] = LGBMClassifier(n_estimators=300, random_state=RANDOM_STATE, n_jobs=-1)
    except ImportError:
        logger.warning("lightgbm not installed -- skipping (pip install lightgbm to enable).")

    try:
        from catboost import CatBoostClassifier
        models["CatBoost"] = CatBoostClassifier(
            iterations=300, verbose=False, random_state=RANDOM_STATE
        )
    except ImportError:
        logger.warning("catboost not installed -- skipping (pip install catboost to enable).")

    return models


def save_bundle(bundle: dict, path: str):
    joblib.dump(bundle, path)
    logger.info(f"Model bundle saved to {path}")


def load_bundle(path: str) -> dict:
    return joblib.load(path)
