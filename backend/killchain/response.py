"""Response plan per incident: proposed actions, approvals, audit trail and a dry-run script.

Kavach never touches the firewall. An approved action can only be exported as a script for a
person to review and run. Values in the script come from the log, which an attacker can influence,
so each one is validated, and a value that fails becomes a manual step instead of a command.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from datetime import UTC, datetime
from pathlib import Path

_INTERNAL = ("10.",)
_SAFE_ACCOUNT = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_SAFE_DOMAIN = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_STATE_FILE = "response_state.json"
_AUDIT_FILE = "response_audit.jsonl"
_MAX_HOST_ACTIONS = 25
_ENTITY_CAP = 50  # matches rules._MAX_ENTITY_VALUES
_LOCK = threading.Lock()

TRANSITIONS = {
    "proposed": ["approved", "rejected"],
    "approved": ["exported", "rejected"],
    "rejected": ["proposed"],
    "exported": [],
}
_LOGGING_TECHNIQUE = "T1562.001"
_POLICY_TECHNIQUE = "T1562.004"
_WEBSHELL_TECHNIQUE = "T1505.003"


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _action(kind: str, target: str, title: str, why: str) -> dict:
    return {"action_id": f"{kind}:{target}", "kind": kind, "target": target, "title": title,
            "why": why}


def build_actions(inc: dict) -> list[dict]:
    """Proposed actions for one incident, most urgent kind first."""
    actions: list[dict] = []
    detections = inc.get("detections", [])
    techniques = {d["technique"]["id"] for d in detections}
    outsiders: list[str] = []
    sources: list[str] = []
    victims: list[str] = []
    for d in detections:
        got_through = d["outcome"] != "blocked"
        command_channel = d["technique"]["tactic"] in ("command-and-control", "discovery")
        for ip in d["entities"].get("src_ip", []):
            if ip.startswith(_INTERNAL):
                if got_through or command_channel:
                    sources.append(ip)
            else:
                outsiders.append(ip)
        for ip in d["entities"].get("dst_ip", []):
            if not ip.startswith(_INTERNAL):
                outsiders.append(ip)
            elif got_through:
                victims.append(ip)
    for ip in dict.fromkeys(outsiders):
        actions.append(_action("block_ip", ip, f"Block external IP {ip}",
                               "It took part in this incident."))
    unique_sources = list(dict.fromkeys(sources))
    for ip in unique_sources[:_MAX_HOST_ACTIONS]:
        actions.append(_action("isolate_host", ip, f"Isolate internal host {ip}",
                               "It acted as a source in this incident."))
    acting = set(sources)
    targets = [v for v in dict.fromkeys(victims) if v not in acting]
    for ip in targets[:_MAX_HOST_ACTIONS]:
        actions.append(_action("inspect_host", ip, f"Inspect host {ip} for compromise",
                               "It received activity that was not blocked."))
    # Never drop hosts silently. Detections store at most 50 entities per role, hence "at least".
    hidden = max(0, len(unique_sources) - _MAX_HOST_ACTIONS) + max(0, len(targets) - _MAX_HOST_ACTIONS)
    if hidden or any(len(d["entities"].get(role, [])) >= _ENTITY_CAP for d in detections
                     for role in ("src_ip", "dst_ip")):
        actions.append(_action("review_hosts", f"incident-{inc.get('incident_id')}",
                               f"Review the full host list for this incident: at least {hidden} more "
                               "hosts are not listed here",
                               "Too many hosts to list one by one; query the log for the rest."))
    for user in dict.fromkeys(u for d in detections for u in d["entities"].get("user", [])):
        actions.append(_action("disable_account", user, f"Disable account {user} and reset its credentials",
                               "It was used in this incident."))
    for domain in dict.fromkeys(v for d in detections for v in d["entities"].get("domain", [])):
        actions.append(_action("block_domain", domain, f"Block domain {domain}",
                               "It took part in this incident."))
    if _LOGGING_TECHNIQUE in techniques:
        actions.append(_action("restore_logging", "firewall", "Re-enable and verify firewall disk logging",
                               "Logging settings were changed."))
    if _POLICY_TECHNIQUE in techniques:
        actions.append(_action("restore_policy", "firewall", "Restore firewall policies from a known-good backup",
                               "Firewall policies were purged."))
    if _WEBSHELL_TECHNIQUE in techniques:
        for ip in dict.fromkeys(victims):
            actions.append(_action("remove_webshell", ip, f"Find and remove the webshell on {ip}",
                                   "Webshell requests reached this server."))
    return actions


def _read_state(run_dir: Path) -> dict:
    path = Path(run_dir) / _STATE_FILE
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def with_status(actions: list[dict], run_dir: Path) -> list[dict]:
    state = _read_state(run_dir)
    return [{**a, "status": state.get(a["action_id"], "proposed")} for a in actions]


def all_actions(incidents: dict[int, dict], run_dir: Path) -> list[dict]:
    """Every action once, listing the incidents that need it, worst incident first."""
    merged: dict[str, dict] = {}
    ranked = sorted(incidents.values(), key=lambda i: -i.get("risk_score", 0))
    for inc in ranked:
        for action in inc.get("response", []):
            row = merged.setdefault(action["action_id"], {**action, "incident_ids": []})
            row["incident_ids"].append(inc["incident_id"])
    return with_status(list(merged.values()), run_dir)


def _audit(run_dir: Path, entry: dict) -> None:
    line = {"timestamp": datetime.now(UTC).isoformat(timespec="seconds"), **entry}
    with (Path(run_dir) / _AUDIT_FILE).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")


def read_audit(run_dir: Path) -> list[dict]:
    path = Path(run_dir) / _AUDIT_FILE
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _write_state(run_dir: Path, state: dict) -> None:
    (Path(run_dir) / _STATE_FILE).write_text(json.dumps(state, indent=1), encoding="utf-8")


def transition(run_dir: Path, action_id: str, to_status: str, known_ids: set[str],
               actor: str = "analyst", note: str = "") -> str:
    """Move one action along the approval path; raises KeyError or ValueError when not allowed."""
    if action_id not in known_ids:
        raise KeyError(action_id)
    with _LOCK:
        state = _read_state(run_dir)
        current = state.get(action_id, "proposed")
        if to_status == "exported" or to_status not in TRANSITIONS.get(current, []):
            raise ValueError(f"Cannot move from {current} to {to_status}")
        state[action_id] = to_status
        _write_state(run_dir, state)
        _audit(run_dir, {"actor": actor, "action_id": action_id, "from": current,
                         "to": to_status, "note": note[:500]})
    return to_status


def _commands(action: dict) -> list[str] | None:
    """FortiOS commands for an action, or None when it needs a person or the value is unsafe."""
    kind, target = action["kind"], action["target"]
    if kind in ("block_ip", "isolate_host"):
        if not _valid_ip(target):
            return None
        name = f"kavach-{'block' if kind == 'block_ip' else 'isolate'}-{target}"
        group = "kavach-blocklist" if kind == "block_ip" else "kavach-isolated"
        return ["config firewall address", f'    edit "{name}"', f"        set subnet {target}/32",
                "    next", "end", "config firewall addrgrp", f'    edit "{group}"',
                f'        append member "{name}"', "    next", "end"]
    if kind == "disable_account" and _SAFE_ACCOUNT.match(target):
        return ["config user local", f'    edit "{target}"', "        set status disable",
                "    next", "end"]
    if kind == "restore_logging":
        return ["config log disk setting", "    set status enable", "end"]
    return None


def export_script(incidents: dict[int, dict], run_dir: Path, actor: str = "analyst") -> str:
    """Script of approved actions, which then become `exported`. Nothing is executed."""
    with _LOCK:
        state = _read_state(run_dir)
        rows = [a for a in all_actions(incidents, run_dir) if state.get(a["action_id"]) == "approved"]
        lines = ["# Kavach response script: DRY RUN. Review every line before use.",
                 "# Kavach has not run these commands and has not tested them on a device.",
                 "# Members are only added to address groups: use the groups in your deny policies.",
                 ""]
        for action in rows:
            lines.append(f"# {_comment(action['title'])} (incidents {action['incident_ids']})")
            commands = _commands(action)
            lines += commands if commands else ["# MANUAL STEP: no command generated for this action."]
            lines.append("")
            state[action["action_id"]] = "exported"
            _audit(run_dir, {"actor": actor, "action_id": action["action_id"], "from": "approved",
                             "to": "exported", "note": ""})
        _write_state(run_dir, state)
    return "\n".join(lines)


def _comment(text: str) -> str:
    """Log-derived text on one line, so it cannot break out of a script comment."""
    return re.sub(r"[\r\n\x00-\x1f\x7f]+", " ", text)
