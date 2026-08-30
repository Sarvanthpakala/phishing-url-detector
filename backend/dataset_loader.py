"""
dataset_loader.py
------------------
The ONLY module that knows anything about a specific dataset's shape.

Responsibility:
    1. Read dataset.csv
    2. Read dataset_config.json
    3. Map the dataset's own URL column -> "url"
    4. Map the dataset's own label column/values -> internal 0/1 convention
    5. Validate (drop nulls, drop duplicate URLs, sanity-check the URL string)
    6. Return a clean pandas DataFrame with exactly two columns: ["url", "label"]

Nothing downstream of this module ever touches the dataset's original
column names again -- feature_extractor.py always recomputes every feature
itself from the "url" column, so it is impossible for training and
inference to drift apart, and impossible for a new dataset's extra
columns to leak in as accidental features.
"""

import json
import os
import re
import pandas as pd

from config import PHISHING, LEGITIMATE, get_logger

logger = get_logger("dataset_loader")

URL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.IGNORECASE)


class DatasetConfigError(Exception):
    pass


def load_dataset_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        raise DatasetConfigError(f"dataset_config.json not found at {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    required = ["url_column", "label_column", "phishing_label_value", "legitimate_label_value"]
    missing = [k for k in required if k not in cfg]
    if missing:
        raise DatasetConfigError(f"dataset_config.json is missing required keys: {missing}")

    return cfg


def _normalize_url(u: str) -> str:
    u = str(u).strip()
    if not u:
        return u
    # Add a scheme if the dataset stored bare hostnames (e.g. "example.com/path")
    if not URL_REGEX.match(u):
        u = "http://" + u
    return u


def load_dataset(csv_path: str, config_path: str) -> pd.DataFrame:
    """
    Returns a DataFrame with exactly two columns: ["url", "label"]
    label is always in the internal convention: 1 = phishing, 0 = legitimate.
    """
    cfg = load_dataset_config(config_path)

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"dataset.csv not found at {csv_path}")

    logger.info(f"Loading dataset '{cfg.get('dataset_name', 'unnamed')}' from {csv_path}")
    df = pd.read_csv(csv_path)

    url_col = cfg["url_column"]
    label_col = cfg["label_column"]

    if url_col not in df.columns:
        raise DatasetConfigError(f"url_column '{url_col}' not found in CSV. Columns present: {list(df.columns)}")
    if label_col not in df.columns:
        raise DatasetConfigError(f"label_column '{label_col}' not found in CSV. Columns present: {list(df.columns)}")

    out = df[[url_col, label_col]].copy()
    out.columns = ["url", "raw_label"]

    before = len(out)
    out = out.dropna(subset=["url", "raw_label"])
    out["url"] = out["url"].astype(str).str.strip()
    out = out[out["url"] != ""]
    dropped_na = before - len(out)

    phishing_val = cfg["phishing_label_value"]
    legit_val = cfg["legitimate_label_value"]

    def _norm(x):
        # Numeric values should compare as numbers (0 == 0.0 == "0"), not as strings.
        try:
            return float(x)
        except (TypeError, ValueError):
            return str(x).strip().lower()

    phishing_norm = _norm(phishing_val)
    legit_norm = _norm(legit_val)

    def map_label(v):
        vn = _norm(v)
        if vn == phishing_norm:
            return PHISHING
        if vn == legit_norm:
            return LEGITIMATE
        return None

    out["label"] = out["raw_label"].apply(map_label)
    unmapped = out["label"].isna().sum()
    if unmapped:
        logger.warning(f"{unmapped} rows had a label value not matching phishing/legitimate config and were dropped.")
    out = out.dropna(subset=["label"])
    out["label"] = out["label"].astype(int)

    out["url"] = out["url"].apply(_normalize_url)

    before_dedup = len(out)
    out = out.drop_duplicates(subset=["url"])
    dropped_dup = before_dedup - len(out)

    out = out[["url", "label"]].reset_index(drop=True)

    logger.info(
        f"Dataset loaded: {len(out)} usable rows "
        f"(dropped {dropped_na} null/empty, {unmapped} unmapped-label, {dropped_dup} duplicate URLs). "
        f"Class balance -> phishing={int((out['label']==PHISHING).sum())}, "
        f"legitimate={int((out['label']==LEGITIMATE).sum())}"
    )

    if out["label"].nunique() < 2:
        raise DatasetConfigError("After loading, only one class is present. Check phishing_label_value/legitimate_label_value in dataset_config.json.")

    return out


if __name__ == "__main__":
    import config as cfgmod
    df = load_dataset(cfgmod.DATASET_CSV_PATH, cfgmod.DATASET_CONFIG_PATH)
    print(df.head())
    print(df["label"].value_counts())
