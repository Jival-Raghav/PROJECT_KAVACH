"""scripts/prepare_blind_edr.py
Masks ground-truth labels and threat/rule annotations from EDR logs to produce a blind dataset.
Extracts and stores ground-truth metadata separately for post-prediction benchmarking.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys


def prepare_blind_edr(
    input_path: str | Path = r"c:\Users\jival\Desktop\mitigata\edr_events.json",
    blind_output_path: str | Path = "data/synthetic/edr_events_blind.jsonl",
    ground_truth_output_path: str | Path = "data/synthetic/edr_ground_truth.json",
) -> dict:
    in_file = Path(input_path)
    if not in_file.exists():
        # Fallback to local workspace if not found at absolute path
        alt = Path("data/edr_events.json")
        if alt.exists():
            in_file = alt
        else:
            raise FileNotFoundError(f"Input file not found: {input_path}")

    blind_out = Path(blind_output_path)
    blind_out.parent.mkdir(parents=True, exist_ok=True)
    gt_out = Path(ground_truth_output_path)
    gt_out.parent.mkdir(parents=True, exist_ok=True)

    ground_truth_events: dict[str, dict] = {}
    attack_count = 0
    benign_count = 0
    technique_counts: dict[str, int] = {}
    tactic_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}

    total_lines = 0

    with open(in_file, "r", encoding="utf-8") as f_in, open(blind_out, "w", encoding="utf-8") as f_out:
        for line in f_in:
            line_str = line.strip()
            if not line_str:
                continue
            total_lines += 1
            raw_event = json.loads(line_str)

            event_obj = raw_event.get("event", {})
            event_id = event_obj.get("id") or f"evt_{total_lines}"

            labels = raw_event.get("labels", {})
            threat = raw_event.get("threat", {})
            rule = raw_event.get("rule", {})

            is_synth = str(labels.get("synthetic", "")).lower() == "true"
            is_sim = str(labels.get("simulated_detection", "")).lower() == "true"
            is_attack = is_synth or is_sim or bool(threat) or bool(rule)

            tech_obj = threat.get("technique", {}) if threat else {}
            t_ids = tech_obj.get("id", [])
            tech_id = t_ids[0] if isinstance(t_ids, list) and t_ids else (t_ids if isinstance(t_ids, str) else None)
            t_names = tech_obj.get("name", [])
            tech_name = t_names[0] if isinstance(t_names, list) and t_names else (t_names if isinstance(t_names, str) else None)

            tactic_obj = threat.get("tactic", {}) if threat else {}
            tac_names = tactic_obj.get("name", [])
            tactic_name = tac_names[0] if isinstance(tac_names, list) and tac_names else (tac_names if isinstance(tac_names, str) else None)

            rule_name = rule.get("name") if rule else None
            rule_id = rule.get("id") if rule else None

            if is_attack:
                attack_count += 1
                if tech_id:
                    technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
                if tactic_name:
                    tactic_counts[tactic_name] = tactic_counts.get(tactic_name, 0) + 1
                if rule_name:
                    rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
            else:
                benign_count += 1

            ground_truth_events[event_id] = {
                "event_id": event_id,
                "is_attack": is_attack,
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic_name": tactic_name,
                "rule_name": rule_name,
                "rule_id": rule_id,
                "timestamp": raw_event.get("@timestamp"),
                "user": raw_event.get("user", {}).get("name"),
                "host": raw_event.get("host", {}).get("name"),
                "action": event_obj.get("action"),
                "category": event_obj.get("category"),
            }

            # ── Masking for Blind Ingestion ──
            # Strip labels, labels_extra, threat, and rule
            sanitized = {k: v for k, v in raw_event.items() if k not in ("labels", "labels_extra", "threat", "rule")}

            # Neutralize event kind and severity so alert flags cannot be used to cheat
            if "event" in sanitized and isinstance(sanitized["event"], dict):
                sanitized_event = dict(sanitized["event"])
                sanitized_event["kind"] = "event"
                sanitized_event["severity"] = 0
                sanitized["event"] = sanitized_event

            f_out.write(json.dumps(sanitized) + "\n")

    # Save Ground Truth
    gt_payload = {
        "metadata": {
            "source_file": str(in_file),
            "total_events": total_lines,
            "attack_count": attack_count,
            "benign_count": benign_count,
            "attack_ratio": round(attack_count / total_lines, 4) if total_lines else 0.0,
            "techniques": technique_counts,
            "tactics": tactic_counts,
            "rules": rule_counts,
        },
        "events": ground_truth_events,
    }

    with open(gt_out, "w", encoding="utf-8") as f_gt:
        json.dump(gt_payload, f_gt, indent=2)

    # Also mirror to desktop mitigata directory if accessible
    desktop_mirror = Path(r"c:\Users\jival\Desktop\mitigata")
    if desktop_mirror.exists() and desktop_mirror.is_dir():
        try:
            import shutil
            shutil.copyfile(blind_out, desktop_mirror / "edr_events_blind.jsonl")
            shutil.copyfile(gt_out, desktop_mirror / "edr_ground_truth.json")
        except Exception:
            pass

    print(f"Masking complete.")
    print(f"Total events processed: {total_lines}")
    print(f"Attacks recorded in ground truth: {attack_count}")
    print(f"Benign events: {benign_count}")
    print(f"Blind dataset written to: {blind_out}")
    print(f"Ground truth written to: {gt_out}")

    return gt_payload["metadata"]


if __name__ == "__main__":
    prepare_blind_edr()
