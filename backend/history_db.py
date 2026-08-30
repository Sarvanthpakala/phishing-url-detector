"""
history_db.py
--------------
Tiny SQLite wrapper for scan history so the frontend can show past scans
and let the user download a CSV report. No ORM needed for this scope.
"""

import sqlite3
import json
import datetime
import csv
import io

from config import HISTORY_DB_PATH, get_logger

logger = get_logger("history_db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    prediction TEXT NOT NULL,
    probability REAL NOT NULL,
    risk_level TEXT NOT NULL,
    model_used TEXT NOT NULL,
    reasons TEXT,
    created_at TEXT NOT NULL
);
"""


def _connect():
    conn = sqlite3.connect(HISTORY_DB_PATH)
    conn.execute(SCHEMA)
    return conn


def init_db():
    conn = _connect()
    conn.commit()
    conn.close()


def log_scan(url: str, prediction: str, probability: float, risk_level: str, model_used: str, reasons: list):
    conn = _connect()
    conn.execute(
        "INSERT INTO scans (url, prediction, probability, risk_level, model_used, reasons, created_at) VALUES (?,?,?,?,?,?,?)",
        (url, prediction, probability, risk_level, model_used, json.dumps(reasons), datetime.datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 100) -> list:
    conn = _connect()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def history_to_csv(limit: int = 1000) -> str:
    rows = get_history(limit)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "url", "prediction", "probability", "risk_level", "model_used", "reasons", "created_at"])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()
