# PhishGuard — AI Phishing URL Detection & Prevention System

A dataset-independent phishing URL detection framework: Flask + scikit-learn
backend, React + Vite + Tailwind frontend. Built for a final-year B.Tech
AI/ML major project.

## Why this design (read before touching anything)

The single most important rule in this codebase:

> **`backend/feature_extractor.py` is the only place features are computed.
> Training and prediction both call it. They can never drift apart.**

The model is trained only on features that can be computed **offline**,
deterministically, from the URL string itself (34 lexical/structural
features — length ratios, entropy, keyword hits, TLD reputation, IP
detection, etc.). Live signals — SSL certificate, DNS, WHOIS, redirect
chains — are gathered separately by `backend/security_checks.py` and shown
to the user as supporting evidence, folded into the *displayed* risk score
through a small transparent rule-based booster. They are **never** part of
the classifier's input vector. This is deliberate: a feature that is
sometimes available and sometimes not (no internet, DNS blocked, rate
limits) would silently change the model's input distribution between
training and serving. Keeping the ML model 100% offline-reproducible, and
layering live intel on top only for explanation, avoids that entirely.

The model also never sees the domain name as a categorical feature, and it
is validated on an **unseen-domain holdout set** carved out by registrable
domain (not by row) at training time — proving it generalizes to domains
it has never encountered rather than memorizing a domain allowlist.

## Project structure

```
phishing-detector/
├── backend/
│   ├── app.py                # Flask REST API (thin — no ML logic here)
│   ├── config.py              # paths, constants, internal label convention
│   ├── train.py                # training pipeline (CV, holdout, plots, PDF)
│   ├── predict.py             # loads bundle, scores a URL
│   ├── dataset_loader.py     # the ONLY module that knows a dataset's shape
│   ├── feature_extractor.py  # the ONLY feature computation module
│   ├── preprocessing.py      # builds the feature matrix + scaling
│   ├── model_manager.py      # candidate models, save/load bundle
│   ├── explainability.py     # reasons + SHAP / permutation-importance
│   ├── security_checks.py    # live SSL/DNS/WHOIS/redirect checks
│   ├── history_db.py          # SQLite scan history
│   ├── utils.py                # plotting + PDF report helpers
│   ├── models/                # model_bundle.joblib (generated)
│   └── reports/                # metrics.json, plots, training_report.pdf (generated)
├── dataset/
│   ├── dataset.csv            # your training data (replace this to retrain on new data)
│   └── dataset_config.json   # the ONLY file you edit when swapping datasets
├── frontend/                  # React + Vite + Tailwind SPA
├── screenshots/
├── static/
└── README.md
```

## Swapping in a new dataset (this is the whole point of the project)

1. Drop your new CSV in as `dataset/dataset.csv`.
2. Edit `dataset/dataset_config.json` — four keys only:

```json
{
  "dataset_name": "your_dataset_name",
  "url_column": "URL",
  "label_column": "ClassLabel",
  "phishing_label_value": 1,
  "legitimate_label_value": 0
}
```

3. Run `python train.py` again.

**No other file changes.** `dataset_loader.py` reads only the URL and
label columns you named — every other column in the CSV is ignored, so a
dataset with completely different pre-computed feature columns (or none at
all) works identically. Every feature the model actually uses is
recomputed from the raw URL by `feature_extractor.py`.

> The CSV shipped in this repo (`url_features_extracted1.csv`, ~101k rows)
> happens to use the **inverted** convention `0 = phishing, 1 = legitimate`
> — the config above reflects that. A dataset using the more common
> `1 = phishing, 0 = legitimate` just needs those two values swapped.

## Setup

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
python train.py               # trains + saves model_bundle.joblib + reports
python app.py                  # starts the API on http://localhost:5000
```

`xgboost`, `lightgbm`, `catboost`, and `shap` are optional — if installed,
`train.py` automatically includes them in the model comparison and
`explainability.py` uses real SHAP values; if not, the pipeline skips them
and falls back to permutation importance without any code changes needed.

### Frontend

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173, proxies /api to :5000
```

## What training actually produces

Running `train.py` on the full shipped dataset (100,872 usable rows after
cleaning) on this machine produced:

| Model | Mean CV Accuracy | Mean CV F1 | Mean CV ROC-AUC |
|---|---|---|---|
| LogisticRegression | 0.9983 | 0.9987 | 0.9999 |
| RandomForest | 0.9991 | 0.9993 | 1.0000 |
| ExtraTrees | 0.9993 | 0.9994 | 1.0000 |
| GradientBoosting | 0.9991 | 0.9993 | 1.0000 |
| AdaBoost | 0.9986 | 0.9988 | 1.0000 |
| **HistGradientBoosting (selected)** | **0.9995** | **0.9996** | **1.0000** |

- Held-out test split: Accuracy 0.9993, F1 0.9995, ROC-AUC 0.99999
- **Unseen-domain holdout** (8,152 domains never seen during training,
  16,370 rows): Accuracy 0.9993, F1 0.9995, ROC-AUC 0.9998

The unseen-domain number matching the ordinary test number is the key
evidence the model is not memorizing domains — see `reports/metrics.json`
and `reports/training_report.pdf` for the full breakdown, confusion
matrix, ROC/PR curves, calibration curve, and feature importance after you
run training.

xgboost/lightgbm/catboost were not available in the environment this was
built in (no internet access to install them) — install them locally and
rerun `train.py` to include them in the comparison; nothing else changes.

## Live verification & the final decision engine (v2)

The ML model is **structure-only by design** (see above) — which means on
its own it will never flag a URL just because its domain doesn't exist or
looks like a typosquat of a famous brand, since it has no way to check
those things. That's exactly why the verdict the user sees is no longer
the raw ML probability. `predict.py` now runs, by default, on every scan:

1. **Domain existence** — `security_checks.check_domain_exists` (DNS resolution)
2. **SSL certificate** — issuer, subject, issued/expiry dates, validity,
   self-signed detection, hostname-vs-certificate match
3. **WHOIS** — registrar, creation/expiry/last-updated dates, domain age,
   registrant country (when the registry exposes it)
4. **DNS** — A, MX, TXT, NS, CNAME records
5. **HTTP/HTTPS** — status code, redirect chain, final URL, whether HTTPS
   is actually enforced end-to-end
6. **Brand-impersonation / typosquat detection** (`brand_similarity.py`) —
   compares the domain (with leetspeak normalization: `0→o`, `1→l`,
   `3→e`...) against a curated list of well-known brands using
   Levenshtein similarity (rapidfuzz if installed, a dependency-free
   pure-python fallback otherwise)
7. **Threat intelligence** (`threat_intel.py`) — pluggable Google Safe
   Browsing / VirusTotal / PhishTank / OpenPhish checks. With no API keys
   configured, each provider reports `"configured": false` honestly rather
   than pretending to have run. Add a key later (e.g. set
   `GOOGLE_SAFE_BROWSING_API_KEY`) and it activates automatically — no
   other code changes.

`decision_engine.py` then combines all of it into one final score:

```
final_score = (0.55 × ML probability) + (0.45 × live-risk score)
```

where the live-risk score is a transparent sum of weighted rules (see
`RULE_WEIGHTS` in `decision_engine.py`) — e.g. a non-resolving domain
contributes 0.55, a suspected brand impersonation contributes 0.35, a
self-signed certificate contributes 0.15, and so on, capped at 1.0. Three
**hard floors** exist for near-certain cases so a confident ML score can't
override real-world ground truth: a domain that doesn't resolve is floored
at 0.85, a confirmed brand impersonation is floored at 0.70, and a
positive threat-intel hit is floored at 0.97.

This is what fixes the original gap: entering a nonsense domain like
`https://skjoidvbn` used to come back "Low Risk" because its URL structure
looked clean. It now correctly comes back **Critical / Phishing**, because
the domain doesn't resolve — regardless of what the (unmodified) ML model
thinks about its lexical structure. The `decision_breakdown` field in the
API response, and the "Final Score Composition" panel in the UI, show
exactly which rules fired and by how much, so the reasoning is never a
black box.

**The ML model, its training pipeline, and the dataset are all unchanged
by this feature** — `train.py`, `model_bundle.joblib`, and `dataset.csv`
are untouched. This is purely a post-processing / decision layer on top of
the existing model's output.

## Enabling threat-intelligence providers (optional)

None of these are required to run the project — every provider reports
`"configured": false` honestly until you set its key:

| Variable | Provider |
|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `PHISHTANK_ENABLED=1` | PhishTank (no key needed, just opt-in — public API is rate-limited) |
| `OPENPHISH_ENABLED=1` | OpenPhish (no key needed, downloads their public feed each check) |

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/predict` | POST `{ "url": "...", "live_intel": true }` | Scan a URL (live_intel defaults to true) |
| `/api/history` | GET `?limit=100` | Recent scans |
| `/api/history/csv` | GET | Download scan history as CSV |
| `/api/metrics` | GET | Training metrics JSON |
| `/api/report/pdf` | GET | Download the training report PDF |
| `/api/health` | GET | Model-ready check |

## Known limitations / honest caveats for the viva

- SHAP is used when installed; otherwise contributions fall back to
  permutation importance computed once at training time (global, not
  per-instance) — still a real, non-fabricated explanation, just less
  precise than true per-prediction SHAP values.
- Live WHOIS/DNS/redirect checks depend on outbound internet access from
  wherever `app.py` runs; they degrade gracefully (return
  `"available": false"`) rather than breaking the scan when offline.
- The "unseen domain" split is approximate (registrable domain = last two
  labels of the hostname), which is a reasonable proxy without pulling in
  a public suffix list, but isn't perfect for multi-part TLDs (e.g.
  `.co.uk`).
