"""The shipped FortiGate rule pack: no IOCs, every rule fires on its pattern, noise stays quiet."""
import random
import re

import pytest
import yaml

from tests.kc_fixture import REPO, at, fg_line, ingest_lines
from killchain.rules import load_rules, run_rules
from killchain.store import open_events

RULES_DIR = REPO / "config/detection_rules"


def _gt_iocs() -> set[str]:
    gt = yaml.safe_load((REPO / "data/ground_truth/firex_planted.yaml").read_text())
    iocs = {"crscore"}
    for sc in gt["scenarios"]:
        for st in sc["steps"]:
            w = st["where"]
            iocs |= {v for v in re.findall(r"(?:srcip|dstip|user)\s*=\s*'([^']+)'", w)}
            iocs |= {v.strip("%.") for v in re.findall(r"hostname LIKE '([^']+)'", w)}
    return {i for i in iocs if "%" not in i}


def test_rule_pack_has_no_iocs():
    text = "\n".join(p.read_text() for p in RULES_DIR.glob("*.y*ml"))
    leaked = sorted(i for i in _gt_iocs() if i in text)
    assert leaked == []


def _sys(when, **kw):
    return fg_line(when, type="event", subtype="system", **kw)


def _fixture(rule_id: str) -> list[str]:
    if rule_id == "KC-RECON-001":
        return [fg_line(at(i * 0.01), action="deny", srcip="9.9.9.9", srcintfrole="wan",
                        dstip="10.10.20.5", dstintfrole="dmz", dstport=p)
                for i, p in enumerate(range(1, 121))]
    if rule_id == "KC-RECON-002":
        return [fg_line(at(i * 0.01), action="deny", srcip="10.10.30.5", srcintfrole="lan",
                        dstip="10.10.20.5", dstintfrole="dmz", dstport=p)
                for i, p in enumerate(range(1, 121))]
    if rule_id == "KC-WEB-001":
        return [fg_line(at(i * 0.3), type="utm", subtype="ips", action="dropped",
                        attack="HTTP.URI.SQL.Injection", srcip="8.8.4.4", srcintfrole="wan",
                        dstip="10.10.20.20", dstintfrole="dmz") for i in range(12)]
    if rule_id == "KC-WEB-002":
        return [fg_line(at(i), type="utm", subtype="webfilter", action="passthrough",
                        url="/uploads/img_1.php", srcip="8.8.4.4", srcintfrole="wan",
                        dstip="10.10.20.20", dstintfrole="dmz") for i in range(6)]
    if rule_id == "KC-C2-001":
        return [fg_line(at(i), type="utm", subtype="ips", action="dropped", attack="Some.Botnet",
                        srcip=f"10.10.40.{i + 1}", srcintfrole="lan", dstip="7.7.7.7",
                        dstintfrole="wan") for i in range(12)]
    if rule_id == "KC-C2-002":
        return [fg_line(at(i * 0.2), type="utm", subtype="dns", action="pass",
                        srcip="10.10.10.9", srcintfrole="lan", dstip="8.8.8.8", dstintfrole="wan",
                        hostname=f"{'a' * 30}{i:06d}.tunnel-example.net") for i in range(60)]
    if rule_id == "KC-C2-003":
        return [fg_line(at(i * 5), action="accept", srcip="10.10.10.9", srcintfrole="lan",
                        dstip="7.7.7.7", dstintfrole="wan", sentbyte=560) for i in range(60)]
    if rule_id == "KC-MAL-001":
        return [fg_line(at(i), type="utm", subtype="virus", action="blocked", virus=f"W{i}/x!tr",
                        srcip="10.10.10.5", srcintfrole="lan", dstip="6.6.6.6",
                        dstintfrole="wan") for i in range(4)]
    if rule_id == "KC-MAL-002":
        return [fg_line(at(0), type="utm", subtype="virus", action="detected", virus="JS/x",
                        srcip="10.10.10.5", srcintfrole="lan", dstip="6.6.6.6",
                        dstintfrole="wan")]
    if rule_id == "KC-EXF-001":
        return [fg_line(at(i * 5), action="accept", srcip="10.10.20.9", srcintfrole="dmz",
                        dstip="7.7.7.7", dstintfrole="wan", sentbyte=20000) for i in range(250)]
    if rule_id in ("KC-LAT-001", "KC-LAT-002"):
        port = 445 if rule_id == "KC-LAT-001" else 3389
        return [fg_line(at(i), action="accept", srcip="10.10.10.9", srcintfrole="lan",
                        dstip=f"10.10.20.{i + 1}", dstintfrole="dmz", dstport=port)
                for i in range(12)]
    if rule_id == "KC-ID-001":
        base = [fg_line(at(i), type="event", subtype="vpn", action="ssl-login", user="ops",
                        srcip="4.4.4.4", srccountry="Japan") for i in range(150)]
        return base + [_sys(at(200), logdesc="Admin login successful", user="ops",
                            srcip="5.5.5.5", srccountry="Brazil", status="success",
                            action="login")]
    if rule_id == "KC-ID-004":
        return [_sys(at(0), logdesc="Admin login successful", user="newadmin", srcip="5.5.5.5",
                     srccountry="Brazil", status="success", action="login")]
    if rule_id == "KC-ID-002":
        base = [fg_line(at(i), type="event", subtype="vpn", action="ssl-login", user="u1",
                        srcip="4.4.4.4", srccountry="Japan") for i in range(150)]
        return base + [fg_line(at(200), type="event", subtype="vpn", action="ssl-login",
                               user="u1", srcip="3.3.3.3", srccountry="Brazil")]
    if rule_id == "KC-ID-003":
        fails = [_sys(at(i * 0.1), logdesc="Admin login failed", user="admin", srcip="9.9.9.9",
                      action="login", status="failed") for i in range(60)]
        return fails + [_sys(at(7), logdesc="Admin login successful", user="admin",
                             srcip="9.9.9.9", action="login", status="success")]
    if rule_id == "KC-PER-001":
        return [_sys(at(0), logdesc="Object attribute configured", user="x", srcip="5.5.5.5",
                     action="Add", msg="Add system.admin backdoor1")]
    if rule_id == "KC-PER-002":
        return [_sys(at(0), logdesc="Object attribute configured", user="x", srcip="5.5.5.5",
                     action="Delete", msg="Delete system.admin backdoor1")]
    if rule_id == "KC-DEF-001":
        return [_sys(at(0), logdesc="Attribute configured", user="x", srcip="5.5.5.5",
                     action="Edit", msg="Attribute 'status' of setting 'log disk setting' "
                                        "changed from 'enable' to 'disable'")]
    if rule_id == "KC-DEF-002":
        return [_sys(at(0), logdesc="Attribute configured", user="x", srcip="5.5.5.5",
                     action="Edit", msg="Objects of 'firewall policy' were purged")]
    raise KeyError(rule_id)


RULE_IDS = ["KC-RECON-001", "KC-RECON-002", "KC-WEB-001", "KC-WEB-002", "KC-C2-001",
            "KC-C2-002", "KC-C2-003", "KC-MAL-001", "KC-MAL-002", "KC-EXF-001", "KC-LAT-001", "KC-LAT-002",
            "KC-ID-001", "KC-ID-002", "KC-ID-003", "KC-ID-004", "KC-PER-001", "KC-PER-002", "KC-DEF-001",
            "KC-DEF-002"]


def test_rule_ids_match_pack():
    assert sorted(r.id for r in load_rules(RULES_DIR)) == sorted(RULE_IDS)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_fires_on_its_pattern(tmp_path, rule_id):
    con = open_events(ingest_lines(tmp_path, _fixture(rule_id)))
    dets = run_rules(con, load_rules(RULES_DIR))
    assert rule_id in {d.rule_id for d in dets}


def _noise() -> list[str]:
    rnd = random.Random(7)
    ext = lambda: f"{rnd.randint(11, 220)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"  # noqa: E731
    lan = lambda: f"10.10.{rnd.choice([10, 30, 40, 50])}.{rnd.randint(1, 254)}"  # noqa: E731
    out = []
    for i in range(500):  # uniform IPS signatures, random pairs, both directions
        if i % 2:
            out.append(fg_line(at(i * 0.5), type="utm", subtype="ips", action="dropped",
                               attack="Mirai.Botnet.Command.Traffic", srcip=lan(),
                               srcintfrole="lan", dstip=ext(), dstintfrole="wan"))
        else:
            out.append(fg_line(at(i * 0.5), type="utm", subtype="ips", action="dropped",
                               attack="HTTP.Server.Authorization.Buffer.Overflow", srcip=ext(),
                               srcintfrole="wan", dstip=f"10.10.20.{rnd.randint(1, 254)}",
                               dstintfrole="dmz"))
    ips = [ext() for _ in range(40)]
    for i in range(2000):  # failed admin logins, never a success
        out.append(_sys(at(i * 0.05), logdesc="Admin login failed", user="admin",
                        srcip=ips[i % 40], action="login", status="failed",
                        reason="name_invalid"))
    for i in range(300):  # blocked malware, random destinations
        out.append(fg_line(at(i), type="utm", subtype="virus", action="blocked",
                           virus=f"W{rnd.randint(1, 31)}/x!tr", srcip=lan(), srcintfrole="lan",
                           dstip=ext(), dstintfrole="wan"))
    for i in range(120):  # one busy but irregular client/server pair
        out.append(fg_line(at(rnd.uniform(0, 600)), action="accept", srcip="10.10.30.7",
                           srcintfrole="lan", dstip="5.6.7.8", dstintfrole="wan", sentbyte=900))
    for i in range(50):  # big single flows
        out.append(fg_line(at(i), action="accept", srcip=lan(), srcintfrole="lan", dstip=ext(),
                           dstintfrole="wan", sentbyte=9_000_000))
    for i in range(300):  # VPN users always from their usual country
        u = i % 3
        out.append(fg_line(at(i), type="event", subtype="vpn", action="ssl-login",
                           user=f"user{u}", srcip=f"4.4.4.{u}", srccountry=["Japan", "India",
                                                                             "Germany"][u]))
    for i in range(200):  # ordinary DNS
        out.append(fg_line(at(i), type="utm", subtype="dns", action="pass", srcip=lan(),
                           srcintfrole="lan", dstip="8.8.8.8", dstintfrole="wan",
                           hostname=rnd.choice(["nytimes.com", "mail.google.com", "x.com"])))
    return out


def test_noise_produces_no_detections(tmp_path):
    con = open_events(ingest_lines(tmp_path, _noise()))
    dets = run_rules(con, load_rules(RULES_DIR))
    assert [d.summary for d in dets] == []


def test_readme_example_rule_loads(tmp_path):
    text = (REPO / "README.md").read_text(encoding="utf-8")
    block = text.split("# config/detection_rules/fortigate.yaml\n", 1)[1].split("```", 1)[0]
    d = tmp_path / "r"
    d.mkdir()
    (d / "x.yaml").write_text("rules:\n" + block, encoding="utf-8")
    (rule,) = load_rules(d)
    assert rule.id == "KC-CUSTOM-001"


def test_new_admin_account_is_not_called_unusual_country(tmp_path):
    con = open_events(ingest_lines(tmp_path, _fixture("KC-ID-004")))
    ids = {d.rule_id for d in run_rules(con, load_rules(RULES_DIR))}
    assert ids == {"KC-ID-004"}
