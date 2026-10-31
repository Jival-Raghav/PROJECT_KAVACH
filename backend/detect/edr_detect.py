"""backend/detect/edr_detect.py
Advanced EDR Behavioral Detection, MITRE ATT&CK Classification, and Attack Path Reconstruction.

Operates strictly on blind CanonicalBundle events without accessing ground truth labels.
Combines:
1. Behavioral detection heuristics for endpoint, network, authentication, and file activities.
2. MITRE ATT&CK Technique & Kill Chain stage tagging.
3. Unsupervised Isolation Forest anomaly scoring on behavioral feature vectors.
4. Attack path reconstruction linking multi-stage adversary progressions across identities and hosts.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from core.models import CanonicalBundle, CanonicalEvent


# Well-known enterprise domains (benign baseline)
BENIGN_DOMAINS = {
    "teams.microsoft.com",
    "www.google.com",
    "outlook.office365.com",
    "slack.com",
    "github.com",
    "s3.amazonaws.com",
    "login.microsoftonline.com",
    "update.microsoft.com",
    "zoom.us",
}

OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SCRIPT_INTERPRETERS = {"powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe", "pwsh.exe"}


def is_private_ip(ip_str: str | None) -> bool:
    if not ip_str:
        return True
    ip = ip_str.strip()
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("127.")
        or ip == "::1"
    )


@dataclass
class EventPrediction:
    event_id: str
    is_anomaly: bool
    confidence: float
    mitre_technique: str | None = None
    mitre_technique_name: str | None = None
    kill_chain_stage: str | None = None
    rule_name: str | None = None
    risk_score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class EDRDetectionResult:
    run_id: str
    total_events: int
    detected_anomalies: int
    event_predictions: dict[str, EventPrediction]
    user_attack_paths: dict[str, list[dict[str, Any]]]
    user_risk_scores: dict[str, float]
    technique_summary: dict[str, int]
    tactic_summary: dict[str, int]


def extract_event_features(events: list[CanonicalEvent]) -> np.ndarray:
    """Extract numeric behavioral features for unsupervised Isolation Forest scoring."""
    rows: list[list[float]] = []

    # Precompute source IP fail frequencies
    source_fails: dict[str, int] = defaultdict(int)
    for e in events:
        if not e.success and e.source_ip:
            source_fails[e.source_ip] += 1

    for e in events:
        ext = e.extra or {}
        raw = e.raw or {}

        proc_name = str(ext.get("process_name") or raw.get("process", {}).get("name") or "").lower()
        parent_name = str(ext.get("parent_process") or raw.get("process", {}).get("parent", {}).get("name") or "").lower()
        cmd_line = str(ext.get("command_line") or raw.get("process", {}).get("command_line") or "").lower()
        dest_domain = str(ext.get("destination_domain") or raw.get("destination", {}).get("domain") or "").lower()
        reg_path = str(ext.get("registry_path") or raw.get("registry", {}).get("path") or "")
        f_ext = str(ext.get("file_extension") or raw.get("file", {}).get("extension") or "").lower()
        f_path = str(ext.get("file_path") or raw.get("file", {}).get("path") or "").lower()

        is_external = 0.0 if is_private_ip(e.source_ip) else 1.0
        fail_flag = 1.0 if not e.success else 0.0
        fail_freq = min(float(source_fails.get(e.source_ip or "", 0)) / 10.0, 5.0)

        office_spawn = 1.0 if (parent_name in OFFICE_PROCESSES and proc_name in SCRIPT_INTERPRETERS) else 0.0
        encoded_cmd = 1.0 if ("-enc" in cmd_line or "-w hidden" in cmd_line or "nop" in cmd_line) else 0.0
        reg_autorun = 1.0 if ("currentversion\\run" in reg_path.lower()) else 0.0
        c2_domain = 1.0 if (dest_domain and dest_domain not in BENIGN_DOMAINS and proc_name in SCRIPT_INTERPRETERS) else 0.0
        ransom_ext = 1.0 if (f_ext == "locked" or f_path.endswith(".locked")) else 0.0
        is_crown = 1.0 if str(e.resource_sensitivity).lower() == "crown" else 0.0

        rows.append([
            is_external,
            fail_flag,
            fail_freq,
            office_spawn,
            encoded_cmd,
            reg_autorun,
            c2_domain,
            ransom_ext,
            is_crown,
        ])

    return np.array(rows, dtype=float)


def run_edr_detection(
    bundle: CanonicalBundle,
    contamination: float = 0.06,
    random_state: int = 42,
) -> EDRDetectionResult:
    """Execute hybrid behavioral heuristics + unsupervised Isolation Forest on blind EDR events."""
    events = bundle.events
    total_events = len(events)
    predictions: dict[str, EventPrediction] = {}

    # 1. Unsupervised Isolation Forest Anomaly Scoring
    X = extract_event_features(events)
    if len(X) > 0 and X.shape[1] > 0:
        iso = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        iso.fit(X)
        raw_scores = iso.decision_function(X)
        # Invert decision function: lower means more anomalous -> map to [0, 100]
        min_s, max_s = raw_scores.min(), raw_scores.max()
        denom = (max_s - min_s) if max_s > min_s else 1.0
        ml_anom_scores = 100.0 * (1.0 - (raw_scores - min_s) / denom)
    else:
        ml_anom_scores = np.zeros(total_events)

    # 2. Count failed logins per source IP for brute-force tracking
    source_fail_counts: dict[str, int] = defaultdict(int)
    for e in events:
        if not e.success and e.source_ip and not is_private_ip(e.source_ip):
            source_fail_counts[e.source_ip] += 1

    technique_summary: dict[str, int] = defaultdict(int)
    tactic_summary: dict[str, int] = defaultdict(int)
    detected_count = 0

    # User timeline tracking for attack path reconstruction
    user_attack_events: dict[str, list[CanonicalEvent]] = defaultdict(list)

    # 3. Behavioral Evaluation per Event
    for idx, e in enumerate(events):
        ext = e.extra or {}
        raw = e.raw or {}

        proc_name = str(ext.get("process_name") or raw.get("process", {}).get("name") or "").lower()
        parent_name = str(ext.get("parent_process") or raw.get("process", {}).get("parent", {}).get("name") or "").lower()
        cmd_line = str(ext.get("command_line") or raw.get("process", {}).get("command_line") or "").lower()
        dest_domain = str(ext.get("destination_domain") or raw.get("destination", {}).get("domain") or "").lower()
        dest_ip = str(ext.get("destination_ip") or raw.get("destination", {}).get("ip") or "").lower()
        reg_path = str(ext.get("registry_path") or raw.get("registry", {}).get("path") or "")
        f_ext = str(ext.get("file_extension") or raw.get("file", {}).get("extension") or "").lower()
        f_path = str(ext.get("file_path") or raw.get("file", {}).get("path") or "").lower()
        winlog_eid = ext.get("winlog_event_id") or raw.get("winlog", {}).get("event_id")
        action = str(e.action or "").lower()

        is_attack = False
        tech_id: str | None = None
        tech_name: str | None = None
        tactic_name: str | None = None
        rule_name: str | None = None
        confidence = 0.0

        # ── Pattern 1: Office spawning scripting engine (T1059.001 - Execution) ──
        if (
            parent_name in OFFICE_PROCESSES
            and (proc_name in SCRIPT_INTERPRETERS or "powershell" in proc_name)
        ):
            is_attack = True
            tech_id = "T1059.001"
            tech_name = "PowerShell"
            tactic_name = "Execution"
            rule_name = "Office application spawned a scripting engine"
            confidence = 0.98

        # ── Pattern 2: Scripting persistence via Registry Run keys (T1547.001 - Persistence) ──
        elif (
            "currentversion\\run" in reg_path.lower()
            and (action in ("registry_value_set", "registry_change") or "registry" in str(raw.get("event", {}).get("category", [])))
            and (proc_name in SCRIPT_INTERPRETERS or "powershell" in proc_name)
        ):
            is_attack = True
            tech_id = "T1547.001"
            tech_name = "Registry Run Keys / Startup Folder"
            tactic_name = "Persistence"
            rule_name = "Autorun key created by scripting engine"
            confidence = 0.98

        # ── Pattern 3: C2 Beaconing via Web Protocols (T1071.001 - Command and Control) ──
        elif (
            (proc_name in SCRIPT_INTERPRETERS or "powershell" in proc_name)
            and (action in ("network_connection", "connection") or "network" in str(raw.get("event", {}).get("category", [])))
            and dest_domain
            and (dest_domain not in BENIGN_DOMAINS)
            and ("bad-domain" in dest_domain or "suspicious" in dest_domain or "exfil" in dest_domain or not is_private_ip(dest_ip))
        ):
            is_attack = True
            tech_id = "T1071.001"
            tech_name = "Web Protocols"
            tactic_name = "Command and Control"
            rule_name = "Beaconing to low-reputation destination"
            confidence = 0.96

        # ── Pattern 4: External High-Rate Brute Force (T1110 - Credential Access) ──
        elif (
            (winlog_eid == 4625 or (action == "user_logon" and not e.success))
            and e.source_ip
            and not is_private_ip(e.source_ip)
            and source_fail_counts.get(e.source_ip, 0) >= 5
        ):
            is_attack = True
            tech_id = "T1110"
            tech_name = "Brute Force"
            tactic_name = "Credential Access"
            rule_name = "High rate of failed logons from single source"
            confidence = 0.95

        # ── Pattern 5: Ransomware / Data Encrypted for Impact (T1486 - Impact) ──
        elif (
            (f_ext == "locked" or f_path.endswith(".locked"))
            and (action in ("file_rename", "file_modified", "file_change") or "file" in str(raw.get("event", {}).get("category", [])))
        ):
            is_attack = True
            tech_id = "T1486"
            tech_name = "Data Encrypted for Impact"
            tactic_name = "Impact"
            rule_name = "Rapid mass file rename to uniform extension"
            confidence = 0.99

        # Fallback to pure ML if anomaly score is exceptionally high (> 85)
        elif ml_anom_scores[idx] >= 88.0:
            is_attack = True
            confidence = round(float(ml_anom_scores[idx]) / 100.0, 2)
            rule_name = "High statistical anomaly outlier"

        risk_score = round(confidence * 100.0 if is_attack else float(ml_anom_scores[idx]) * 0.2, 1)

        if is_attack:
            detected_count += 1
            if tech_id:
                technique_summary[tech_id] += 1
            if tactic_name:
                tactic_summary[tactic_name] += 1

            # Tag the canonical event with the predicted values
            e.mitre_technique = tech_id
            e.kill_chain_stage = tactic_name
            user_attack_events[e.user_key].append(e)

        pred = EventPrediction(
            event_id=e.event_id,
            is_anomaly=is_attack,
            confidence=confidence,
            mitre_technique=tech_id,
            mitre_technique_name=tech_name,
            kill_chain_stage=tactic_name,
            rule_name=rule_name,
            risk_score=risk_score,
            details={
                "process": proc_name,
                "parent": parent_name,
                "user": e.user_key,
                "system": e.system,
                "timestamp": e.timestamp,
            },
        )
        predictions[e.event_id] = pred

    # 4. Attack Path Reconstruction per User
    # Standard Kill Chain order
    KILL_CHAIN_ORDER = {
        "Initial Access": 1,
        "Execution": 2,
        "Persistence": 3,
        "Privilege Escalation": 4,
        "Defense Evasion": 5,
        "Credential Access": 6,
        "Discovery": 7,
        "Lateral Movement": 8,
        "Collection": 9,
        "Command and Control": 10,
        "Exfiltration": 11,
        "Impact": 12,
    }

    user_attack_paths: dict[str, list[dict[str, Any]]] = {}
    user_risk_scores: dict[str, float] = {}

    for u_key, ev_list in user_attack_events.items():
        # Sort chronologically
        sorted_evs = sorted(ev_list, key=lambda x: str(x.timestamp))
        unique_stages: list[dict[str, Any]] = []
        seen_stage_tech: set[tuple[str, str]] = set()

        for ev in sorted_evs:
            stage = ev.kill_chain_stage or "Unknown"
            tech = ev.mitre_technique or "Unknown"
            pair = (stage, tech)
            if pair not in seen_stage_tech:
                seen_stage_tech.add(pair)
                unique_stages.append({
                    "stage": stage,
                    "stage_order": KILL_CHAIN_ORDER.get(stage, 99),
                    "technique": tech,
                    "system": ev.system,
                    "action": ev.action,
                    "timestamp": ev.timestamp,
                    "event_id": ev.event_id,
                })

        # Sort stages according to attack progression
        reconstructed_path = sorted(unique_stages, key=lambda x: (x["stage_order"], x["timestamp"]))
        user_attack_paths[u_key] = reconstructed_path

        # User risk score is based on number of distinct stages compromised
        stage_coverage = len(set(s["stage"] for s in unique_stages))
        user_risk_scores[u_key] = min(100.0, round(stage_coverage * 20.0 + len(ev_list) * 0.5, 1))

    return EDRDetectionResult(
        run_id=bundle.run_id,
        total_events=total_events,
        detected_anomalies=detected_count,
        event_predictions=predictions,
        user_attack_paths=user_attack_paths,
        user_risk_scores=user_risk_scores,
        technique_summary=dict(technique_summary),
        tactic_summary=dict(tactic_summary),
    )
