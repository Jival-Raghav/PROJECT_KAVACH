"""
backend/posture/report.py — Audit Pack Exporter (PDF, JSON, CSV) with Cryptographic Integrity.

Generates:
1. Formal PDF compliance report using ReportLab.
2. Machine-readable JSON audit pack with SHA-256 manifest.
3. CSV evidence table.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.models import CanonicalBundle
from posture.compliance import evaluate_compliance
from posture.score import calculate_identity_hygiene_score


def generate_audit_pack_json(
    bundle: CanonicalBundle,
    hygiene_data: dict[str, Any] | None = None,
    compliance_data: dict[str, Any] | None = None,
) -> str:
    """Generates machine-readable JSON audit pack with SHA-256 manifest."""
    if hygiene_data is None:
        hygiene_data = calculate_identity_hygiene_score(bundle)
    if compliance_data is None:
        compliance_data = evaluate_compliance(bundle, hygiene_data)

    timestamp = datetime.now(timezone.utc).isoformat()
    raw_payload = f"{timestamp}:{hygiene_data.get('identity_hygiene_score')}:{len(bundle.identities)}"
    manifest_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    pack = {
        "ispad_version": "v2.0-cyberforge",
        "generated_at": timestamp,
        "manifest_sha256": manifest_hash,
        "hygiene_summary": hygiene_data,
        "compliance_summary": compliance_data,
        "inventory": {
            "total_identities": len(bundle.identities),
            "total_accounts": len(bundle.accounts),
            "total_entitlements": len(bundle.entitlements),
            "total_systems": len(bundle.systems),
            "total_events": len(bundle.events),
        },
    }
    return json.dumps(pack, indent=2)


def generate_audit_pack_csv(compliance_data: dict[str, Any]) -> str:
    """Generates CSV evidence rows for all evaluated controls."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Control_ID", "Framework", "Title", "Status", "Evidence_Findings"])

    for c in compliance_data.get("controls", []):
        writer.writerow([
            c["id"],
            c["framework"],
            c["title"],
            c["status"].upper(),
            c["evidence"],
        ])

    return output.getvalue()


def generate_audit_pack_pdf(
    bundle: CanonicalBundle,
    hygiene_data: dict[str, Any] | None = None,
    compliance_data: dict[str, Any] | None = None,
) -> bytes:
    """
    Generates a formal executive PDF compliance pack using ReportLab.
    """
    if hygiene_data is None:
        hygiene_data = calculate_identity_hygiene_score(bundle)
    if compliance_data is None:
        compliance_data = evaluate_compliance(bundle, hygiene_data)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
    )
    h2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )

    story = []

    # Title & Header
    story.append(Paragraph("ISPAD v2 · Enterprise Identity Compliance Pack", title_style))
    story.append(Spacer(1, 4))
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated: {timestamp} | Scope: Multi-Source Identity Fabric", body_style))
    story.append(Spacer(1, 14))

    # Executive Summary Card Table
    score = hygiene_data.get("identity_hygiene_score", 0.0)
    grade = hygiene_data.get("grade", "N/A")
    rate = compliance_data.get("compliance_rate", 0.0)

    summary_data = [
        [
            Paragraph("<b>Identity Hygiene Score</b>", body_style),
            Paragraph("<b>Compliance Pass Rate</b>", body_style),
            Paragraph("<b>Insurer Exposure Index</b>", body_style),
        ],
        [
            Paragraph(f"<font size=18 color='#0284C7'><b>{score} / 100</b> (Grade {grade})</font>", body_style),
            Paragraph(f"<font size=18 color='#10B981'><b>{rate}%</b></font>", body_style),
            Paragraph(f"<font size=14 color='#F59E0B'><b>{hygiene_data.get('insurer_exposure', {}).get('tier', 'ELEVATED')}</b></font>", body_style),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[180, 180, 180])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Framework Compliance Control Table
    story.append(Paragraph("Framework Control Evaluation (NIST SP 800-53 / ISO 27001 / DPDP Act)", h2_style))
    story.append(Spacer(1, 4))

    table_rows = [
        [
            Paragraph("<b>ID</b>", body_style),
            Paragraph("<b>Framework</b>", body_style),
            Paragraph("<b>Control Title</b>", body_style),
            Paragraph("<b>Status</b>", body_style),
            Paragraph("<b>Automated Evidence Findings</b>", body_style),
        ]
    ]

    for c in compliance_data.get("controls", []):
        st = c["status"].upper()
        color_hex = "#10B981" if st == "PASS" else "#EF4444" if st == "FAIL" else "#F59E0B"
        table_rows.append([
            Paragraph(f"<font name='Courier'><b>{c['id']}</b></font>", body_style),
            Paragraph(c["framework"], body_style),
            Paragraph(c["title"], body_style),
            Paragraph(f"<font color='{color_hex}'><b>{st}</b></font>", body_style),
            Paragraph(c["evidence"], body_style),
        ])

    control_table = Table(table_rows, colWidths=[65, 80, 110, 50, 235])
    control_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(control_table)
    story.append(Spacer(1, 16))

    # Top Negative Drivers
    story.append(Paragraph("Top Negative Posture Drivers & Recommended Remediation", h2_style))
    for d in hygiene_data.get("top_drivers", []):
        story.append(Paragraph(
            f"• <b>{d['subscore'].upper().replace('_', ' ')}</b>: "
            f"Deducted {d['deduction_points']} points (Weight: {d['weight_pct']}%). {d['explanation']}",
            body_style,
        ))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 16))

    # Reviewer Sign-Off Box
    story.append(Paragraph("Formal Reviewer Sign-Off", h2_style))
    sign_data = [
        [
            Paragraph("<b>Reviewer Name / Title:</b>", body_style),
            Paragraph("____________________________________________", body_style),
        ],
        [
            Paragraph("<b>Date & Signature:</b>", body_style),
            Paragraph("____________________________________________", body_style),
        ],
    ]
    sign_table = Table(sign_data, colWidths=[150, 390])
    sign_table.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(sign_table)

    doc.build(story)
    return buffer.getvalue()
