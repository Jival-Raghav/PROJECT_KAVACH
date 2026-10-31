"""tests/test_edr_pipeline.py
Unit and integration tests for EDR blind dataset masking, ECS canonical adaptation,
behavioral anomaly detection, MITRE ATT&CK classification, and benchmarking.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ingest.edr_adapter import load_edr_bundle
from detect.edr_detect import run_edr_detection
from scripts.prepare_blind_edr import prepare_blind_edr
from scripts.bench_edr_eval import evaluate_edr_benchmarks


@pytest.fixture(scope="module")
def prepared_edr_data(tmp_path_factory):
    blind_path = Path("data/synthetic/edr_events_blind.jsonl")
    gt_path = Path("data/synthetic/edr_ground_truth.json")

    # If already generated, use them; otherwise run prepare
    if not blind_path.exists() or not gt_path.exists():
        prepare_blind_edr(
            input_path=r"c:\Users\jival\Desktop\mitigata\edr_events.json",
            blind_output_path=blind_path,
            ground_truth_output_path=gt_path,
        )

    return blind_path, gt_path


def test_blind_dataset_integrity(prepared_edr_data):
    blind_path, gt_path = prepared_edr_data
    assert blind_path.exists()
    assert gt_path.exists()

    with open(blind_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            data = json.loads(line)
            # Ensure no ground truth labels leaked
            assert "labels" not in data
            assert "labels_extra" not in data
            assert "threat" not in data
            assert "rule" not in data
            assert data["event"]["kind"] == "event"
            assert data["event"]["severity"] == 0
            if idx > 100:
                break


def test_edr_canonical_bundle_loading(prepared_edr_data):
    blind_path, _ = prepared_edr_data
    bundle = load_edr_bundle(blind_path)

    assert bundle.run_id == "edr_blind"
    assert len(bundle.events) == 10000
    assert len(bundle.identities) > 0
    assert len(bundle.accounts) > 0
    assert len(bundle.systems) > 0

    first_ev = bundle.events[0]
    assert first_ev.event_id is not None
    assert first_ev.timestamp != ""
    assert first_ev.user_key != ""
    assert first_ev.action != ""
    # Ensure event labels remain None before detection
    assert first_ev.label is None


def test_edr_detection_and_mitre_classification(prepared_edr_data):
    blind_path, _ = prepared_edr_data
    bundle = load_edr_bundle(blind_path)
    result = run_edr_detection(bundle)

    assert result.total_events == 10000
    assert result.detected_anomalies == 500

    # Verify all 5 simulated MITRE ATT&CK techniques are recognized
    expected_techniques = {"T1059.001", "T1071.001", "T1110", "T1486", "T1547.001"}
    assert set(result.technique_summary.keys()) == expected_techniques

    # Verify Kill Chain stages
    expected_tactics = {"Execution", "Command and Control", "Credential Access", "Impact", "Persistence"}
    assert set(result.tactic_summary.keys()) == expected_tactics

    # Verify attack path reconstruction
    assert len(result.user_attack_paths) > 0
    sample_user = list(result.user_attack_paths.keys())[0]
    path = result.user_attack_paths[sample_user]
    assert len(path) >= 2


def test_edr_benchmarks_pass_prd_criteria(prepared_edr_data):
    blind_path, gt_path = prepared_edr_data
    results = evaluate_edr_benchmarks(
        blind_file=blind_path,
        ground_truth_file=gt_path,
        report_md_path="reports/test_edr_benchmark.md",
        report_json_path="reports/test_edr_benchmark.json",
    )

    metrics = results["metrics"]
    # PRD Target: Recall > 90% Great (> 70% Good)
    assert metrics["recall"] >= 0.90
    assert metrics["recall_grade"] == "GREAT"

    # PRD Target: False Alarm Rate < 10% Great (< 30% Good)
    assert metrics["false_alarm_rate"] <= 0.10
    assert metrics["fpr_grade"] == "GREAT"

    # PRD Target: MITRE Technique Match > 85% Great (> 60% Good)
    assert metrics["mitre_technique_accuracy"] >= 0.85
    assert metrics["mitre_grade"] == "GREAT"

    assert metrics["true_positives"] == 500
    assert metrics["false_positives"] == 0
