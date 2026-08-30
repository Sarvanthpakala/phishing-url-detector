"""
preprocessing.py
-----------------
Builds the numeric feature matrix from the (url, label) DataFrame produced
by dataset_loader.py. Uses feature_extractor.extract_feature_vector() for
every single row -- the same function predict.py calls for a single URL --
so the matrix training sees and the vector inference sees are guaranteed
to have identical columns, in identical order.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from feature_extractor import FEATURE_NAMES, extract_feature_vector
from config import get_logger

logger = get_logger("preprocessing")


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """df must have a 'url' column. Returns a DataFrame with FEATURE_NAMES columns."""
    logger.info(f"Extracting {len(FEATURE_NAMES)} features for {len(df)} URLs...")
    rows = [extract_feature_vector(u) for u in df["url"].tolist()]
    feat_df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    return feat_df


def fit_scaler(X: pd.DataFrame) -> StandardScaler:
    scaler = StandardScaler()
    scaler.fit(X.values)
    return scaler


def apply_scaler(scaler: StandardScaler, X: pd.DataFrame) -> np.ndarray:
    return scaler.transform(X.values)


def registrable_domain(url: str) -> str:
    """Cheap 'domain' used only to split train/holdout so the unseen-domain
    validation set genuinely contains domains absent from training -- not
    used as a model feature."""
    from urllib.parse import urlparse
    host = urlparse(url if "://" in url else "http://" + url).hostname or url
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
