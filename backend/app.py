"""
app.py
-------
Flask REST API. Thin layer only: no model or training logic lives here --
everything is delegated to predict.py, history_db.py, and config.py. This
keeps the API decoupled from the ML internals as required.
"""

import os
import json
from flask import Flask, request, jsonify, send_file, Response

import config
from config import get_logger
import history_db
from predict import predict_url

logger = get_logger("app")

app = Flask(__name__)

try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    logger.warning("flask-cors not installed -- adding permissive CORS headers manually (pip install flask-cors for the real thing).")

    @app.after_request
    def _add_cors_headers(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        return resp

history_db.init_db()


@app.route("/api/health", methods=["GET"])
def health():
    model_ready = os.path.exists(config.MODEL_BUNDLE_PATH)
    return jsonify({"status": "ok", "model_ready": model_ready})


@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    include_live_intel = bool(data.get("live_intel", True))

    if not url:
        return jsonify({"error": "Field 'url' is required."}), 400

    try:
        result = predict_url(url, include_live_intel=include_live_intel, include_shap=True)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        logger.exception("Prediction failed")
        return jsonify({"error": f"Prediction failed: {e}"}), 500

    try:
        history_db.log_scan(
            url=result["url"],
            prediction=result["verdict"],
            probability=result["displayed_probability"],
            risk_level=result["risk_level"],
            model_used=result["model_used"],
            reasons=result["reasons"],
        )
    except Exception:
        logger.exception("Failed to log scan history (non-fatal)")

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 100))
    return jsonify(history_db.get_history(limit))


@app.route("/api/history/csv", methods=["GET"])
def history_csv():
    csv_text = history_db.history_to_csv()
    return Response(
        csv_text, mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_history.csv"},
    )


@app.route("/api/metrics", methods=["GET"])
def metrics():
    if not os.path.exists(config.METRICS_JSON_PATH):
        return jsonify({"error": "No metrics available yet. Run train.py first."}), 404
    with open(config.METRICS_JSON_PATH) as f:
        return jsonify(json.load(f))


@app.route("/api/report/pdf", methods=["GET"])
def report_pdf():
    if not os.path.exists(config.TRAINING_REPORT_PDF):
        return jsonify({"error": "No training report available yet. Run train.py first."}), 404
    return send_file(config.TRAINING_REPORT_PDF, as_attachment=True, download_name="training_report.pdf")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
