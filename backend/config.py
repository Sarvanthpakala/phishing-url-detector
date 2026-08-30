"""
config.py
---------
Single source of truth for paths and constants used across the project.

INTERNAL LABEL CONVENTION (fixed, independent of any dataset's own encoding):
    1 = PHISHING / MALICIOUS
    0 = LEGITIMATE

dataset_loader.py is the ONLY place that translates a dataset's own label
values (whatever they are, per dataset_config.json) into this convention.
Every other module (feature_extractor, preprocessing, model_manager,
train, predict, app) only ever sees 0/1 in this convention and never needs
to know how any particular dataset encoded its labels.
"""

import os
import logging

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)

DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")
DATASET_CSV_PATH = os.path.join(DATASET_DIR, "dataset.csv")
DATASET_CONFIG_PATH = os.path.join(DATASET_DIR, "dataset_config.json")

MODELS_DIR = os.path.join(BACKEND_DIR, "models")
REPORTS_DIR = os.path.join(BACKEND_DIR, "reports")
ARTIFACTS_DIR = os.path.join(BACKEND_DIR, "artifacts")
HISTORY_DB_PATH = os.path.join(ARTIFACTS_DIR, "history.db")

for _d in (MODELS_DIR, REPORTS_DIR, ARTIFACTS_DIR):
    os.makedirs(_d, exist_ok=True)

MODEL_BUNDLE_PATH = os.path.join(MODELS_DIR, "model_bundle.joblib")
METRICS_JSON_PATH = os.path.join(REPORTS_DIR, "metrics.json")
TRAINING_REPORT_PDF = os.path.join(REPORTS_DIR, "training_report.pdf")

# ---------------------------------------------------------------------------
# Internal label convention
# ---------------------------------------------------------------------------
PHISHING = 1
LEGITIMATE = 0

# ---------------------------------------------------------------------------
# Candidate models. Every entry is guarded by try/except at import time in
# model_manager.py -- if a library (xgboost / lightgbm / catboost) is not
# installed, that single model is skipped and everything else still runs.
# This is what lets the pipeline degrade gracefully on any machine.
# ---------------------------------------------------------------------------
CANDIDATE_MODELS = [
    "logistic_regression",
    "random_forest",
    "extra_trees",
    "gradient_boosting",
    "adaboost",
    "hist_gradient_boosting",
    "xgboost",     # optional, requires `pip install xgboost`
    "lightgbm",    # optional, requires `pip install lightgbm`
    "catboost",    # optional, requires `pip install catboost`
]

RANDOM_STATE = 42
N_SPLITS = 5          # stratified k-fold
TEST_SIZE = 0.2
HOLDOUT_UNSEEN_DOMAIN_SIZE = 0.15  # carved out by *domain*, not by row

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
