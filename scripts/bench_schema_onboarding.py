"""Benchmark log onboarding with a log whose correct translation is known.

Rewrites the analysed part of firex-10G.log using different field names and values, lets the LLM learn the
format, scores the mapping against the known answer, then runs the pipeline and compares incidents with a
normal FortiGate run. The names are still descriptive and the values unchanged in meaning, so this is
easier than a truly foreign log: read the result as an upper limit.

    python scripts/bench_schema_onboarding.py --source firex-10G.log --workdir DIR --baseline firex_parallel
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from config import get_settings  # noqa: E402
from killchain.onboard import (_KV, _unquote, approve_schema, build_schema, load_concepts, save_schema,  # noqa: E402
                               scan_log)
from killchain.pipeline import run_killchain  # noqa: E402
from killchain.rules import load_rules  # noqa: E402

LAST_ANALYSED_LINE = 3_848_247  # firex-10G.log: the frozen clock starts on the next line
FROZEN_KEPT = 2_000  # enough for the frozen-clock filter to find it

FIELD_NAMES = {
    "eventtime": "log_time_ns", "logid": "message_code", "type": "log_category", "subtype": "log_subcategory",
    "level": "priority", "action": "disposition", "srcip": "origin_address", "srcport": "origin_port",
    "srcintf": "ingress_if", "srcintfrole": "ingress_trust", "dstip": "target_address", "dstport": "target_port",
    "dstintf": "egress_if", "dstintfrole": "egress_trust", "proto": "ip_number", "service": "network_service",
    "policyid": "matched_rule", "sessionid": "connection_id", "srccountry": "origin_geo", "dstcountry": "target_geo",
    "sentbyte": "octets_out", "rcvdbyte": "octets_in", "duration": "conn_seconds", "app": "detected_app",
    "appcat": "app_group", "apprisk": "app_danger", "logdesc": "event_label", "msg": "narrative", "user": "principal",
    "ui": "mgmt_channel", "method": "access_via", "status": "verdict", "reason": "denial_cause", "hostname": "dns_or_host",
    "url": "request_path", "catdesc": "site_group", "attack": "ids_signature", "attackid": "ids_number",
    "severity": "ids_rating", "virus": "av_finding", "crscore": "reputation_points",
}
VALUE_NAMES = {
    "type": {"traffic": "flow", "event": "platform_event", "utm": "inspection_alert"},
    "subtype": {"forward": "session", "system": "management", "webfilter": "url_control", "dns": "name_lookup",
                "ips": "intrusion", "app-ctrl": "application_control", "virus": "antimalware", "vpn": "remote_access",
                "ha": "cluster", "sdwan": "wan_health", "connector": "cloud_link", "dhcp": "address_lease"},
    "action": {"accept": "permit", "deny": "reject_by_rule", "dropped": "ips_drop", "blocked": "av_block",
               "detected": "seen_not_stopped", "ssl-login": "sslvpn_logon", "tunnel-up": "tunnel_established",
               "pass": "inspected_ok", "passthrough": "url_allowed", "login": "admin_auth"},
    "srcintfrole": {"wan": "untrust", "lan": "trust", "dmz": "perimeter"},
    "dstintfrole": {"wan": "untrust", "lan": "trust", "dmz": "perimeter"},
    "logdesc": {"Admin login successful": "Operator signed in", "Admin login failed": "Operator sign-in rejected",
                "Attribute configured": "Setting modified", "Object attribute configured": "Configuration object changed"},
}
# A second vocabulary, kept apart from the first so a fix made after one run is measured on names it never saw.
FIELD_NAMES_B = {
    "eventtime": "emitted_at_ns", "logid": "record_type_code", "type": "stream", "subtype": "module", "level": "urgency",
    "action": "fw_result", "srcip": "initiator", "srcport": "initiator_svc_port", "srcintf": "rx_link",
    "srcintfrole": "rx_exposure", "dstip": "responder", "dstport": "responder_svc_port", "dstintf": "tx_link",
    "dstintfrole": "tx_exposure", "proto": "l4_number", "service": "svc_label", "policyid": "acl_entry",
    "sessionid": "flow_key", "srccountry": "initiator_nation", "dstcountry": "responder_nation", "sentbyte": "volume_up",
    "rcvdbyte": "volume_down", "duration": "lifetime_s", "app": "l7_name", "appcat": "l7_family", "apprisk": "l7_hazard",
    "logdesc": "occurrence", "msg": "free_text", "user": "identity", "ui": "console_path", "method": "console_transport",
    "status": "end_state", "reason": "end_state_why", "hostname": "named_host", "url": "web_path", "catdesc": "web_family",
    "attack": "detector_rule", "attackid": "detector_rule_no", "severity": "detector_grade", "virus": "sample_verdict",
    "crscore": "trust_penalty",
}
VALUE_NAMES_B = {
    "type": {"traffic": "netflow", "event": "appliance", "utm": "threat_engine"},
    "subtype": {"forward": "transit", "system": "appliance_admin", "webfilter": "web_gateway", "dns": "resolver",
                "ips": "ids_engine", "app-ctrl": "l7_engine", "virus": "file_scanner", "vpn": "ssl_gateway",
                "ha": "failover", "sdwan": "link_monitor", "connector": "api_sync", "dhcp": "lease_server"},
    "action": {"accept": "forwarded", "deny": "acl_refused", "dropped": "ids_discarded", "blocked": "scanner_stopped",
               "detected": "scanner_noted", "ssl-login": "gateway_logon", "tunnel-up": "gateway_tunnel_open",
               "pass": "l7_ok", "passthrough": "web_ok", "login": "console_auth"},
    "srcintfrole": {"wan": "public", "lan": "private", "dmz": "semi_public"},
    "dstintfrole": {"wan": "public", "lan": "private", "dmz": "semi_public"},
    "logdesc": {"Admin login successful": "Console access granted", "Admin login failed": "Console access refused",
                "Attribute configured": "Device parameter updated", "Object attribute configured": "Managed entry updated"},
}
# A third vocabulary, used only after the batching fix.
FIELD_NAMES_C = {
    "eventtime": "observed_nanos", "logid": "catalog_ref", "type": "feed", "subtype": "feature", "level": "importance",
    "action": "enforcement", "srcip": "client_host", "srcport": "client_socket", "srcintf": "entry_nic",
    "srcintfrole": "entry_side", "dstip": "server_host", "dstport": "server_socket", "dstintf": "exit_nic",
    "dstintfrole": "exit_side", "proto": "transport_no", "service": "traffic_class", "policyid": "ruleset_line",
    "sessionid": "exchange_ref", "srccountry": "client_region", "dstcountry": "server_region", "sentbyte": "payload_tx",
    "rcvdbyte": "payload_rx", "duration": "open_for", "app": "software", "appcat": "software_kind", "apprisk": "software_rating",
    "logdesc": "happening", "msg": "commentary", "user": "account_handle", "ui": "admin_entry", "method": "admin_wire",
    "status": "finish", "reason": "finish_note", "hostname": "looked_up_name", "url": "page", "catdesc": "page_kind",
    "attack": "exploit_pattern", "attackid": "pattern_ref", "severity": "pattern_weight", "virus": "infected_with",
    "crscore": "bad_points",
}
VALUE_NAMES_C = {
    "type": {"traffic": "conversation", "event": "device_note", "utm": "inspection"},
    "subtype": {"forward": "routed", "system": "device_ops", "webfilter": "site_check", "dns": "lookup",
                "ips": "exploit_guard", "app-ctrl": "software_check", "virus": "file_guard", "vpn": "remote_user",
                "ha": "pairing", "sdwan": "uplink", "connector": "integration", "dhcp": "ip_lease"},
    "action": {"accept": "passed", "deny": "ruleset_stop", "dropped": "guard_kill", "blocked": "file_kill",
               "detected": "file_flagged", "ssl-login": "remote_signin", "tunnel-up": "remote_channel_up",
               "pass": "software_seen", "passthrough": "site_seen", "login": "console_try"},
    "srcintfrole": {"wan": "outside", "lan": "inside", "dmz": "buffer"},
    "dstintfrole": {"wan": "outside", "lan": "inside", "dmz": "buffer"},
    "logdesc": {"Admin login successful": "Device admin entered", "Admin login failed": "Device admin turned away",
                "Attribute configured": "Option altered", "Object attribute configured": "Stored item altered"},
}
# A fourth vocabulary in the style of real vendor logs, written after the word lists were fixed.
# It comes from general knowledge of how vendors name things, so it is not a real vendor sample.
FIELD_NAMES_D = {
    "eventtime": "timestamp_ns", "logid": "log_code", "type": "log_kind", "subtype": "log_module", "level": "syslog_severity",
    "action": "fw_decision", "srcip": "src_addr", "srcport": "src_port_num", "srcintf": "input_interface",
    "srcintfrole": "input_zone_name", "dstip": "dst_addr", "dstport": "dst_port_num", "dstintf": "output_interface",
    "dstintfrole": "output_zone_name", "proto": "ipproto", "service": "svc_name", "policyid": "acl_id",
    "sessionid": "conn_id", "srccountry": "src_geo_country", "dstcountry": "dst_geo_country", "sentbyte": "bytes_tx_total",
    "rcvdbyte": "bytes_rx_total", "duration": "conn_duration", "app": "app_id", "appcat": "app_class", "apprisk": "app_rating",
    "logdesc": "activity", "msg": "activity_detail", "user": "login_name", "ui": "admin_source", "method": "login_protocol",
    "status": "auth_result", "reason": "auth_failure", "hostname": "dest_fqdn", "url": "http_uri", "catdesc": "web_category_name",
    "attack": "ips_sig_name", "attackid": "ips_sig_id", "severity": "ips_level", "virus": "av_threat", "crscore": "rep_score",
}
VALUE_NAMES_D = {
    "type": {"traffic": "TRAFFIC", "event": "SYSTEM", "utm": "THREAT"},
    "subtype": {"forward": "fw_session", "system": "admin_audit", "webfilter": "URL Filtering", "dns": "DNS Security",
                "ips": "Threat Prevention", "app-ctrl": "App-ID", "virus": "Anti-Virus", "vpn": "GlobalProtect",
                "ha": "HA", "sdwan": "SD-WAN", "connector": "cloud", "dhcp": "DHCP"},
    "action": {"accept": "allow", "deny": "policy-deny", "dropped": "reset-both", "blocked": "file-blocked",
               "detected": "alert", "ssl-login": "portal-login", "tunnel-up": "gateway-connected",
               "pass": "app-allowed", "passthrough": "url-allowed", "login": "auth"},
    "srcintfrole": {"wan": "untrust", "lan": "trust", "dmz": "dmz-zone"},
    "dstintfrole": {"wan": "untrust", "lan": "trust", "dmz": "dmz-zone"},
    "logdesc": {"Admin login successful": "Administrator authentication succeeded",
                "Admin login failed": "Administrator authentication failed",
                "Attribute configured": "Configuration setting changed",
                "Object attribute configured": "Configuration object changed"},
}
DROPPED = {"date", "time", "tz"}  # the rewritten log keeps one timestamp field


def _write_value(v: str) -> str:
    return f'"{v}"' if re.search(r'[\s"=]', v) or not v else v


def scramble(source: Path, target: Path) -> int:
    written = 0
    with open(source, "rb") as src, open(target, "w", encoding="utf-8", newline="\n") as out:
        for n, raw in enumerate(src, 1):
            if n > LAST_ANALYSED_LINE + FROZEN_KEPT:
                break
            parts = []
            for k, v in _KV.findall(raw.decode("utf-8").rstrip("\r\n")):
                if k in DROPPED:
                    continue
                v = _unquote(v)
                v = VALUE_NAMES.get(k, {}).get(v, v)
                parts.append(f"{FIELD_NAMES.get(k, 'x_' + k)}={_write_value(v)}")
            out.write(" ".join(parts) + "\n")
            written += 1
    return written


def score(schema: dict) -> dict:
    truth = {new: old for old, new in FIELD_NAMES.items() if old != "eventtime"}
    fields = schema["fields"]
    relevant = {f: c for f, c in truth.items() if f in schema["review"]["how_mapped"]
                or f in schema["review"]["unmapped_log_fields"]}
    right = sorted(f for f, c in relevant.items() if fields.get(f) == c)
    wrong = {f: {"expected": relevant[f], "got": fields[f]} for f in relevant if f in fields and fields[f] != relevant[f]}
    missed = {f: relevant[f] for f in relevant if f not in fields}
    invented = {f: c for f, c in fields.items() if f not in truth}

    concepts = load_concepts()["values"]
    pairs = {(col, new): old for col, table in VALUE_NAMES.items() for old, new in table.items()
             if old in concepts.get(col, {})}
    got = schema.get("values") or {}
    v_right = sum(got.get(col, {}).get(new) == old for (col, new), old in pairs.items())
    v_wrong = {f"{col}={new}": {"expected": old, "got": got.get(col, {}).get(new)} for (col, new), old in pairs.items()
               if got.get(col, {}).get(new) != old}
    value_sources = schema["review"].get("how_values_mapped", {})
    return {"values_by_words": sum(v == "common words" for t in value_sources.values() for v in t.values()),
            "values_by_llm": sum(v == "llm" for t in value_sources.values() for v in t.values()),
            "fields_total": len(relevant), "fields_right": len(right), "fields_wrong": wrong, "fields_missed": missed,
            "fields_invented": invented, "fields_by_llm": sum(m["by"] == "llm" for m in schema["review"]["how_mapped"].values()),
            "values_total": len(pairs), "values_right": v_right, "values_wrong": v_wrong,
            "timestamp_right": schema["timestamp"]["field"] == FIELD_NAMES["eventtime"], "llm_calls": schema["review"]["llm_calls"],
            "warnings": schema["review"]["warnings"], "rejected": schema["review"]["rejected"]}


def _incidents(run_dir: Path) -> list[dict]:
    doc = json.loads((run_dir / "incidents.json").read_text(encoding="utf-8"))
    return doc if isinstance(doc, list) else doc.get("incidents", list(doc.values()))


def _key(i: dict) -> tuple:
    return (i["title"], round(i["risk_score"], 1), i["raw_alert_count"], tuple(sorted(d["detection_id"] for d in i["detections"])))


def compare(baseline: Path, run_dir: Path) -> dict:
    a, b = {_key(i) for i in _incidents(baseline)}, {_key(i) for i in _incidents(run_dir)}
    return {"baseline_incidents": len(a), "translated_incidents": len(b), "identical": len(a & b),
            "only_in_baseline": sorted(k[0] for k in a - b), "only_in_translated": sorted(k[0] for k in b - a)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--baseline", default="firex_parallel")
    ap.add_argument("--run-id", default="onboard_test")
    ap.add_argument("--words-only", action="store_true", help="use common words alone, with no LLM")
    ap.add_argument("--vocabulary", choices=["a", "b", "c", "d"], default="a")
    a = ap.parse_args()
    if a.vocabulary != "a":
        FIELD_NAMES.clear()
        names = {"b": (FIELD_NAMES_B, VALUE_NAMES_B), "c": (FIELD_NAMES_C, VALUE_NAMES_C), "d": (FIELD_NAMES_D, VALUE_NAMES_D)}
        FIELD_NAMES.update(names[a.vocabulary][0])
        VALUE_NAMES.clear()
        VALUE_NAMES.update(names[a.vocabulary][1])
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    work = Path(a.workdir)
    work.mkdir(parents=True, exist_ok=True)
    log, schema_path = work / "scrambled.log", work / "scrambled_schema.yaml"
    runs = Path(get_settings().KILLCHAIN_DATA_DIR) / "runs"

    def say(s: str) -> None:
        print(f"[bench] {s}", flush=True)

    if not log.exists():
        say("writing the rewritten log")
        say(f"{scramble(Path(a.source), log):,} lines written")
    start = time.perf_counter()
    scan = scan_log(log)
    scan_s = time.perf_counter() - start
    say(f"scanned {scan['total']:,} lines in {scan_s:.0f}s")

    usage = []
    client = None
    if not a.words_only:
        from llm.client import get_mapper_client

        client = get_mapper_client()

    def llm(messages: list[dict]) -> str:
        if client is None:
            return "{}"
        t = time.perf_counter()
        size = sum(len(m["content"]) for m in messages)
        reply = client.chat(messages, temperature=0.0, max_tokens=1500)
        usage.append({"prompt_chars": size, "reply_chars": len(reply), "seconds": round(time.perf_counter() - t, 1)})
        say(f"LLM call: {size:,} prompt chars, {len(reply):,} reply chars, {usage[-1]['seconds']}s")
        return reply

    start = time.perf_counter()
    schema = build_schema(scan, llm, "scrambled", pause_seconds=0 if a.words_only else 35.0, progress=say)
    learn_s = time.perf_counter() - start
    save_schema(schema, schema_path)
    result = {"scan_seconds": round(scan_s, 1), "learn_seconds": round(learn_s, 1), "llm_usage": usage, "mapping": score(schema)}
    print(json.dumps(result["mapping"], indent=1))

    approve_schema(schema_path)  # this benchmark approves automatically, because it scores against the known answer
    say("running the pipeline on the rewritten log")
    meta = run_killchain(log, runs / a.run_id, Path(get_settings().KILLCHAIN_RULES_DIR), schema_path=schema_path,
                         progress=lambda s: say(f"pipeline: {s}"))
    result["pipeline_seconds"] = meta["total_seconds"]
    result["peak_rss_mb"] = meta["peak_rss_mb"]
    result["rule_coverage"] = {k: v for k, v in meta["rule_coverage"].items() if k != "rules"}
    result["rules_not_running"] = [r for r in meta["rule_coverage"]["rules"] if r["status"] != "can_run"]
    result["incidents"] = compare(runs / a.baseline, runs / a.run_id)
    result["rule_count"] = len(load_rules(Path(get_settings().KILLCHAIN_RULES_DIR)))
    (work / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps({"SUMMARY": {"vocabulary": a.vocabulary, "words_only": a.words_only,
                                  "fields": f"{result['mapping']['fields_right']}/{result['mapping']['fields_total']}",
                                  "values": f"{result['mapping']['values_right']}/{result['mapping']['values_total']}",
                                  "incidents": f"{result['incidents']['identical']}/{result['incidents']['baseline_incidents']}",
                                  "extra_incidents": len(result["incidents"]["only_in_translated"]),
                                  "llm_calls": result["mapping"]["llm_calls"],
                                  "fields_by_llm": result["mapping"]["fields_by_llm"]}}))
    print(json.dumps({k: result[k] for k in ("scan_seconds", "learn_seconds", "pipeline_seconds", "peak_rss_mb", "rule_coverage",
                                             "rules_not_running", "incidents")}, indent=1))


if __name__ == "__main__":
    main()
