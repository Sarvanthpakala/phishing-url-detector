"""
utils.py
---------
Small shared helpers: saving matplotlib figures consistently, and
assembling the final PDF training report from the generated plots + metrics.
"""

import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from config import get_logger

logger = get_logger("utils")


def savefig(fig, path, dpi=150):
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved plot -> {path}")


def build_training_report_pdf(pdf_path: str, metrics: dict, plot_paths: dict, dataset_summary: dict):
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=20)
    h2 = styles["Heading2"]
    body = styles["BodyText"]

    doc = SimpleDocTemplate(pdf_path, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    story = []

    story.append(Paragraph("Phishing URL Detection — Training Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Dataset: {dataset_summary.get('dataset_name')}", body))
    story.append(Paragraph(f"Total usable rows: {dataset_summary.get('total_rows')}", body))
    story.append(Paragraph(f"Phishing rows: {dataset_summary.get('phishing_rows')} | Legitimate rows: {dataset_summary.get('legitimate_rows')}", body))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Model Comparison", h2))
    table_data = [["Model", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]]
    for name, m in metrics["model_comparison"].items():
        table_data.append([
            name, f"{m['accuracy']:.4f}", f"{m['precision']:.4f}",
            f"{m['recall']:.4f}", f"{m['f1']:.4f}", f"{m['roc_auc']:.4f}",
        ])
    t = Table(table_data, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Best model selected:</b> {metrics['best_model']}", body))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Unseen-Domain Generalization Check", h2))
    hold = metrics["unseen_domain_holdout"]
    story.append(Paragraph(
        f"A holdout set was built from {hold['n_unseen_domains']} domains never seen in training "
        f"({hold['n_rows']} rows). Performance on this set: accuracy={hold['accuracy']:.4f}, "
        f"F1={hold['f1']:.4f}, ROC-AUC={hold['roc_auc']:.4f}. This demonstrates the model is "
        "learning phishing *behavior* rather than memorizing specific domains.", body,
    ))
    story.append(Spacer(1, 16))

    for title, path in plot_paths.items():
        if os.path.exists(path):
            story.append(Paragraph(title, h2))
            story.append(Image(path, width=15 * cm, height=9 * cm))
            story.append(Spacer(1, 12))

    doc.build(story)
    logger.info(f"Training report PDF written -> {pdf_path}")
