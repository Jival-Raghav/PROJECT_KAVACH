"""backend/ingest/edr_adapter.py
Adapter for loading Elastic Common Schema (ECS) / EDR JSON/JSONL datasets into CanonicalBundle.
Preserves all process tree, registry, network destination, and authentication context in CanonicalEvent.raw.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEntitlement,
    CanonicalEvent,
    CanonicalIdentity,
    CanonicalSystem,
    OrgContext,
)


def load_edr_bundle(
    file_path: str | Path = "data/synthetic/edr_events_blind.jsonl",
    run_id: str = "edr_blind",
) -> CanonicalBundle:
    """Reads blind EDR JSON Lines data and converts into a CanonicalBundle."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"EDR dataset not found: {file_path}")

    events: list[CanonicalEvent] = []
    seen_users: set[str] = set()
    seen_hosts: dict[str, str] = {}
    user_hosts: dict[str, set[str]] = {}

    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            data = json.loads(line_str)

            event_obj = data.get("event", {})
            eid = event_obj.get("id") or f"edr_evt_{idx}"
            ts = data.get("@timestamp", "")

            user_obj = data.get("user", {})
            user_name = user_obj.get("name") or "unknown"
            seen_users.add(user_name)

            host_obj = data.get("host", {})
            host_name = host_obj.get("name") or host_obj.get("hostname") or "unknown_host"

            # Incur sensitivity based on infrastructure role
            host_upper = host_name.upper()
            if "DC" in host_upper or "DB" in host_upper:
                host_sens = "crown"
            elif "SRV" in host_upper or "FILE" in host_upper:
                host_sens = "high"
            else:
                host_sens = "medium"
            seen_hosts[host_name] = host_sens

            user_hosts.setdefault(user_name, set()).add(host_name)

            action = event_obj.get("action")
            if not action:
                cats = event_obj.get("category", [])
                action = cats[0] if isinstance(cats, list) and cats else "event"

            # Determine resource from relevant sub-structures
            file_obj = data.get("file", {})
            reg_obj = data.get("registry", {})
            dest_obj = data.get("destination", {})
            proc_obj = data.get("process", {})

            resource = (
                file_obj.get("path")
                or reg_obj.get("path")
                or dest_obj.get("domain")
                or dest_obj.get("ip")
                or proc_obj.get("command_line")
                or proc_obj.get("name")
                or host_name
            )

            # Source IP
            src_obj = data.get("source", {})
            source_ip = src_obj.get("ip")
            if not source_ip:
                host_ips = host_obj.get("ip", [])
                if isinstance(host_ips, list) and host_ips:
                    source_ip = str(host_ips[0])
                elif isinstance(host_ips, str):
                    source_ip = host_ips

            # Success flag
            outcome = str(event_obj.get("outcome", "")).lower()
            winlog_eid = data.get("winlog", {}).get("event_id")
            success = (outcome != "failure") and (winlog_eid != 4625)

            events.append(
                CanonicalEvent(
                    event_id=eid,
                    timestamp=ts,
                    user_key=user_name,
                    action=action,
                    resource=resource,
                    system=host_name,
                    resource_sensitivity=host_sens,
                    success=success,
                    source_ip=source_ip,
                    label=None,  # strictly blind
                    mitre_technique=None,  # to be predicted by detection engine
                    kill_chain_stage=None,  # to be predicted by detection engine
                    raw=data,
                    extra={
                        "host_os": host_obj.get("os", {}).get("full"),
                        "process_name": proc_obj.get("name"),
                        "process_pid": proc_obj.get("pid"),
                        "parent_process": proc_obj.get("parent", {}).get("name"),
                        "command_line": proc_obj.get("command_line"),
                        "destination_ip": dest_obj.get("ip"),
                        "destination_domain": dest_obj.get("domain"),
                        "destination_port": dest_obj.get("port"),
                        "registry_path": reg_obj.get("path"),
                        "file_path": file_obj.get("path"),
                        "file_extension": file_obj.get("extension"),
                        "winlog_event_id": winlog_eid,
                    },
                )
            )

    # Reconstruct identities
    identities: list[CanonicalIdentity] = []
    accounts: list[CanonicalAccount] = []
    entitlements: list[CanonicalEntitlement] = []

    for u in sorted(seen_users):
        # Department inference from assigned workstation names
        hosts_for_u = user_hosts.get(u, set())
        dept = "IT"
        for h in hosts_for_u:
            hu = h.upper()
            if "FIN" in hu:
                dept = "Finance"
                break
            elif "HR" in hu:
                dept = "Human Resources"
                break
            elif "ENG" in hu:
                dept = "Engineering"
                break
            elif "SALES" in hu:
                dept = "Sales"
                break

        is_svc = u.lower().startswith("svc_")
        identities.append(
            CanonicalIdentity(
                identity_id=u,
                full_name=u,
                email=f"{u}@corp.local",
                department=dept,
                job_title="Service Account" if is_svc else f"{dept} Specialist",
                employment_status="active",
                extra={"is_service": is_svc},
            )
        )

        for h in hosts_for_u:
            accounts.append(
                CanonicalAccount(
                    account_id=f"{u}@{h}",
                    system=h,
                    username=u,
                    account_type="service" if is_svc else "human",
                    privilege_level="elevated" if is_svc or "DC" in h.upper() else "standard",
                    extra={"identity_id": u},
                )
            )

    systems = [
        CanonicalSystem(system=h_name, sensitivity=h_sens)
        for h_name, h_sens in seen_hosts.items()
    ]

    return CanonicalBundle(
        run_id=run_id,
        identities=identities,
        accounts=accounts,
        entitlements=entitlements,
        events=events,
        systems=systems,
        org_context=OrgContext(),
    )
