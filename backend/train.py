"""
train.py
---------
End-to-end training pipeline:
    1. Load dataset via dataset_loader (dataset-agnostic)
    2. Build feature matrix via preprocessing + feature_extractor (canonical)
    3. Carve out an UNSEEN-DOMAIN holdout set (by registrable domain, not by row)
       so we can prove the model generalizes instead of memorizing domains
    4. Stratified K-Fold CV + comparison across every available candidate model
    5. Pick the best model by mean CV F1, refit on the full training split
    6. Evaluate the best model on: (a) the ordinary test split, (b) the
       unseen-domain holdout
    7. Generate EDA + evaluation plots, a PDF report, and save the model bundle
"""

import os
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve, precision_recall_curve, classification_report,
)
from sklearn.calibration import calibration_curve
from sklearn.inspection import permutation_importance

import config
from config import get_logger
from dataset_loader import load_dataset
from preprocessing import build_feature_matrix, fit_scaler, apply_scaler, registrable_domain
from model_manager import get_candidate_models, save_bundle
from feature_extractor import FEATURE_NAMES
from utils import savefig, build_training_report_pdf

logger = get_logger("train")


def carve_unseen_domain_holdout(df: pd.DataFrame, holdout_frac: float, seed: int):
    domains = df["url"].apply(registrable_domain)
    unique_domains = np.array(domains.unique().tolist(), dtype=object)
    rng = np.random.default_rng(seed)
    rng.shuffle(unique_domains)
    n_holdout_domains = max(1, int(len(unique_domains) * holdout_frac))
    holdout_domains = set(unique_domains[:n_holdout_domains])

    is_holdout = domains.isin(holdout_domains)
    holdout_df = df[is_holdout].reset_index(drop=True)
    remaining_df = df[~is_holdout].reset_index(drop=True)
    return remaining_df, holdout_df, len(holdout_domains)


def evaluate(model, X, y) -> dict:
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "roc_auc": roc_auc_score(y, proba) if len(set(y)) > 1 else float("nan"),
    }


def run_cv_comparison(models: dict, X: np.ndarray, y: np.ndarray, n_splits: int, seed: int) -> dict:
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    comparison = {}
    for name, model in models.items():
        t0 = time.time()
        fold_metrics = []
        for train_idx, val_idx in skf.split(X, y):
            m = _clone(model)
            m.fit(X[train_idx], y[train_idx])
            fold_metrics.append(evaluate(m, X[val_idx], y[val_idx]))
        agg = {k: float(np.mean([fm[k] for fm in fold_metrics])) for k in fold_metrics[0]}
        agg["cv_seconds"] = round(time.time() - t0, 1)
        comparison[name] = agg
        logger.info(f"[{name}] CV mean -> acc={agg['accuracy']:.4f} f1={agg['f1']:.4f} roc_auc={agg['roc_auc']:.4f} ({agg['cv_seconds']}s)")
    return comparison


def _clone(model):
    from sklearn.base import clone
    return clone(model)


def main():
    t_start = time.time()
    logger.info("=== STAGE 1: Load dataset ===")
    df = load_dataset(config.DATASET_CSV_PATH, config.DATASET_CONFIG_PATH)

    logger.info("=== STAGE 2: Carve unseen-domain holdout ===")
    train_pool_df, holdout_df, n_holdout_domains = carve_unseen_domain_holdout(
        df, config.HOLDOUT_UNSEEN_DOMAIN_SIZE, config.RANDOM_STATE
    )
    logger.info(f"Train pool: {len(train_pool_df)} rows | Unseen-domain holdout: {len(holdout_df)} rows across {n_holdout_domains} domains")

    logger.info("=== STAGE 3: Feature extraction ===")
    X_pool_df = build_feature_matrix(train_pool_df)
    y_pool = train_pool_df["label"].values
    X_holdout_df = build_feature_matrix(holdout_df)
    y_holdout = holdout_df["label"].values

    X_train_df, X_test_df, y_train, y_test = train_test_split(
        X_pool_df, y_pool, test_size=config.TEST_SIZE, stratify=y_pool, random_state=config.RANDOM_STATE
    )

    logger.info("=== STAGE 4: Scaling ===")
    scaler = fit_scaler(X_train_df)
    X_train = apply_scaler(scaler, X_train_df)
    X_test = apply_scaler(scaler, X_test_df)
    X_holdout = apply_scaler(scaler, X_holdout_df)

    logger.info("=== STAGE 5: Candidate models + CV comparison ===")
    models = get_candidate_models()
    logger.info(f"Candidate models available on this machine: {list(models.keys())}")
    cv_comparison = run_cv_comparison(models, X_train, y_train, config.N_SPLITS, config.RANDOM_STATE)

    best_name = max(cv_comparison, key=lambda n: cv_comparison[n]["f1"])
    logger.info(f"Best model by mean CV F1: {best_name}")

    logger.info("=== STAGE 6: Refit best model on full training split ===")
    best_model = _clone(models[best_name])
    best_model.fit(X_train, y_train)

    test_metrics = evaluate(best_model, X_test, y_test)
    holdout_metrics = evaluate(best_model, X_holdout, y_holdout)
    logger.info(f"Held-out test metrics: {test_metrics}")
    logger.info(f"UNSEEN-DOMAIN holdout metrics: {holdout_metrics}")

    logger.info("=== STAGE 7: Plots ===")
    plot_paths = {}

    fig, ax = plt.subplots(figsize=(5, 4))
    df["label"].map({0: "Legitimate", 1: "Phishing"}).value_counts().plot(kind="bar", ax=ax, color=["#2563eb", "#dc2626"])
    ax.set_title("Class Distribution")
    p = os.path.join(config.REPORTS_DIR, "class_distribution.png")
    savefig(fig, p); plot_paths["Class Distribution"] = p

    fig, ax = plt.subplots(figsize=(10, 8))
    corr = X_pool_df.corr()
    sns.heatmap(corr, cmap="coolwarm", center=0, ax=ax, cbar=True, xticklabels=True, yticklabels=True)
    ax.set_title("Feature Correlation")
    p = os.path.join(config.REPORTS_DIR, "feature_correlation.png")
    savefig(fig, p); plot_paths["Feature Correlation"] = p

    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
    elif hasattr(best_model, "coef_"):
        importances = np.abs(best_model.coef_[0])
    else:
        logger.info(f"{best_name} has no native importances -- computing permutation importance (this can take a moment)...")
        perm = permutation_importance(
            best_model, X_test[:2000], y_test[:2000], n_repeats=5,
            random_state=config.RANDOM_STATE, n_jobs=-1,
        )
        importances = np.clip(perm.importances_mean, 0, None)
    order = np.argsort(importances)[::-1]
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.barh([FEATURE_NAMES[i] for i in order][:20][::-1], importances[order][:20][::-1], color="#7c3aed")
    ax.set_title(f"Feature Importance ({best_name})")
    p = os.path.join(config.REPORTS_DIR, "feature_importance.png")
    savefig(fig, p); plot_paths["Feature Importance"] = p

    proba_test = best_model.predict_proba(X_test)[:, 1]
    pred_test = (proba_test >= 0.5).astype(int)

    cm = confusion_matrix(y_test, pred_test)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Legit", "Phishing"], yticklabels=["Legit", "Phishing"], ax=ax)
    ax.set_title("Confusion Matrix (test split)"); ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    p = os.path.join(config.REPORTS_DIR, "confusion_matrix.png")
    savefig(fig, p); plot_paths["Confusion Matrix"] = p

    fpr, tpr, _ = roc_curve(y_test, proba_test)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, label=f"AUC={roc_auc_score(y_test, proba_test):.4f}", color="#dc2626")
    ax.plot([0, 1], [0, 1], "--", color="gray")
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate"); ax.set_title("ROC Curve"); ax.legend()
    p = os.path.join(config.REPORTS_DIR, "roc_curve.png")
    savefig(fig, p); plot_paths["ROC Curve"] = p

    prec, rec, _ = precision_recall_curve(y_test, proba_test)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(rec, prec, color="#2563eb")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision"); ax.set_title("Precision-Recall Curve")
    p = os.path.join(config.REPORTS_DIR, "precision_recall_curve.png")
    savefig(fig, p); plot_paths["Precision-Recall Curve"] = p

    frac_pos, mean_pred = calibration_curve(y_test, proba_test, n_bins=10)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(mean_pred, frac_pos, marker="o", color="#16a34a", label=best_name)
    ax.plot([0, 1], [0, 1], "--", color="gray", label="Perfectly calibrated")
    ax.set_xlabel("Mean predicted probability"); ax.set_ylabel("Fraction of positives"); ax.set_title("Calibration Curve"); ax.legend()
    p = os.path.join(config.REPORTS_DIR, "calibration_curve.png")
    savefig(fig, p); plot_paths["Calibration Curve"] = p

    fig, ax = plt.subplots(figsize=(8, 5))
    names = list(cv_comparison.keys())
    f1s = [cv_comparison[n]["f1"] for n in names]
    order2 = np.argsort(f1s)
    ax.barh([names[i] for i in order2], [f1s[i] for i in order2], color="#0891b2")
    ax.set_title("Model Comparison (mean CV F1)"); ax.set_xlim(0, 1)
    p = os.path.join(config.REPORTS_DIR, "model_comparison.png")
    savefig(fig, p); plot_paths["Model Comparison (CV F1)"] = p

    logger.info("=== STAGE 8: Save artifacts ===")
    bundle = {
        "model": best_model,
        "model_name": best_name,
        "scaler": scaler,
        "feature_names": FEATURE_NAMES,
        "trained_on_rows": int(len(X_train_df)),
        "dataset_name": json.load(open(config.DATASET_CONFIG_PATH)).get("dataset_name"),
        "global_feature_importances": dict(zip(FEATURE_NAMES, [float(v) for v in importances])),
    }
    save_bundle(bundle, config.MODEL_BUNDLE_PATH)

    metrics = {
        "best_model": best_name,
        "model_comparison": cv_comparison,
        "test_split_metrics": test_metrics,
        "unseen_domain_holdout": {
            **holdout_metrics,
            "n_unseen_domains": n_holdout_domains,
            "n_rows": int(len(holdout_df)),
        },
        "classification_report_test": classification_report(y_test, pred_test, target_names=["Legitimate", "Phishing"], output_dict=True),
        "training_seconds": round(time.time() - t_start, 1),
    }
    with open(config.METRICS_JSON_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics saved -> {config.METRICS_JSON_PATH}")

    dataset_summary = {
        "dataset_name": bundle["dataset_name"],
        "total_rows": int(len(df)),
        "phishing_rows": int((df["label"] == 1).sum()),
        "legitimate_rows": int((df["label"] == 0).sum()),
    }
    build_training_report_pdf(config.TRAINING_REPORT_PDF, metrics, plot_paths, dataset_summary)

    logger.info(f"=== DONE in {round(time.time()-t_start,1)}s. Best model: {best_name} | Test F1={test_metrics['f1']:.4f} | Unseen-domain F1={holdout_metrics['f1']:.4f} ===")


if __name__ == "__main__":
    main()
