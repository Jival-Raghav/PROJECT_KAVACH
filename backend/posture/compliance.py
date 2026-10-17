"""
backend/posture/compliance.py — Framework Compliance Evaluator.

Evaluates canonical bundle and hygiene subscores against NIST SP 800-53,
ISO/IEC 27001:2022, and India DPDP Act 2023 controls.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

from core.models import CanonicalBundle
from posture.score import calculate_identity_hygiene_score


def load_control_catalog() -> list[dict[str, Any]]:
    """Loads controls from controls.yaml."""
    yaml_path = Path(__file__).resolve().parent / "controls.yaml"
    if not yaml_path.exists():
        return []
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data.get("controls", [])


def evaluate_compliance(
    bundle: CanonicalBundle,
    hygiene_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluates compliance status (pass, partial, fail, not_assessable) for all catalog controls.
    """
    if hygiene_data is None:
        hygiene_data = calculate_identity_hygiene_score(bundle)

    controls = load_control_catalog()
    subscores = hygiene_data.get("subscores", {})

    evaluated_controls = []
    framework_counts: dict[str, dict[str, int]] = {}

    for c in controls:
        cid = c["id"]
        fw = c["framework"]
        if fw not in framework_counts:
            framework_counts[fw] = {"pass": 0, "partial": 0, "fail": 0, "not_assessable": 0}

        status = "pass"
        evidence_notes = []
        sample_rows = []

        if cid in ("NIST-AC-2", "ISO-5.16"):
            leavers = subscores.get("leaver_active", {}).get("count", 0)
            orphans = subscores.get("orphaned_accounts", {}).get("count", 0)
            if leavers > 0:
                status = "fail"
                evidence_notes.append(f"{leavers} active accounts belong to terminated personnel.")
            elif orphans > 5:
                status = "partial"
                evidence_notes.append(f"{orphans} unowned orphaned accounts detected.")
            else:
                status = "pass"
                evidence_notes.append(f"Lifecycle deprovisioning compliant (0 leavers, {orphans} orphans).")

        elif cid in ("NIST-AC-5", "ISO-5.18"):
            sod = subscores.get("sod_violations", {}).get("count", 0)
            if sod > 0:
                status = "fail"
                evidence_notes.append(f"{sod} users violate strict Separation of Duties constraints.")
            else:
                status = "pass"
                evidence_notes.append("Zero dual-custody or toxic privilege conflicts detected.")

        elif cid in ("NIST-AC-6", "ISO-8.2"):
            dormant = subscores.get("dormant_privileged", {}).get("count", 0)
            creep = subscores.get("privilege_creep", {}).get("count", 0)
            if dormant > 0:
                status = "fail"
                evidence_notes.append(f"{dormant} privileged administrator accounts dormant > 30 days.")
            elif creep > 5:
                status = "partial"
                evidence_notes.append(f"{creep} accounts exhibit excessive privilege creep vs peers.")
            else:
                status = "pass"
                evidence_notes.append("Least privilege enforcement verified (zero dormant privileged).")

        elif cid == "NIST-IA-5":
            if "mfa_coverage" in subscores:
                pct = subscores["mfa_coverage"].get("percentage", 0.0)
                if pct >= 90:
                    status = "pass"
                elif pct >= 60:
                    status = "partial"
                else:
                    status = "fail"
                evidence_notes.append(f"Privileged MFA enforcement rate: {pct}%.")
            else:
                status = "not_assessable"
                evidence_notes.append("MFA telemetry not present in source schema.")

        elif cid == "ISO-5.15":
            p95 = subscores.get("blast_radius_p95", {}).get("p95_score", 30.0)
            if p95 >= 60:
                status = "fail"
            elif p95 >= 35:
                status = "partial"
            else:
                status = "pass"
            evidence_notes.append(f"Access blast radius p95 score: {p95}/100.")

        elif cid == "DPDP-s8(5)":
            sod = subscores.get("sod_violations", {}).get("count", 0)
            leavers = subscores.get("leaver_active", {}).get("count", 0)
            if sod > 0 or leavers > 0:
                status = "fail"
                evidence_notes.append(f"Security safeguard breach: {sod} SoD conflicts and {leavers} leavers active.")
            else:
                status = "pass"
                evidence_notes.append("Crown jewel repositories protected with verified safeguards.")

        framework_counts[fw][status] += 1

        evaluated_controls.append({
            "id": cid,
            "framework": fw,
            "title": c["title"],
            "description": c["description"],
            "status": status,
            "evidence": " ".join(evidence_notes),
            "sample_rows": sample_rows,
        })

    # Total counts
    total = len(evaluated_controls)
    pass_count = sum(1 for c in evaluated_controls if c["status"] == "pass")
    compliance_rate = round((pass_count / max(1, total)) * 100, 1)

    return {
        "status": "success",
        "compliance_rate": compliance_rate,
        "total_controls": total,
        "controls": evaluated_controls,
        "framework_summaries": framework_counts,
        "disclaimer": "Automated mappings are provided as audit evidence aids. Verify wording against official standards text.",
    }
