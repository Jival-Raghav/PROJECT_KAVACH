"""Actor linking: proven activity joins IPs and accounts; failed logins and shared IPs do not."""
from datetime import datetime

from killchain.actors import MAX_USERS_PER_IP, build_actors, link_incidents
from killchain.models import Incident
from killchain.store import open_events
from tests.kc_fixture import at, fg_line, ingest_lines


def _sys(when, **kw):
    return fg_line(when, type="event", subtype="system", **kw)


def _vpn(when, user, ip, country="Japan"):
    return fg_line(when, type="event", subtype="vpn", action="ssl-login", user=user, srcip=ip,
                   srccountry=country)


def _admin(when, user, ip, country="Russia"):
    return _sys(when, logdesc="Admin login successful", user=user, srcip=ip, srccountry=country,
                action="login", status="success")


def _actors(tmp_path, lines):
    return build_actors(open_events(ingest_lines(tmp_path, lines)))


def test_same_account_links_two_ips_and_countries(tmp_path):
    (actor,) = _actors(tmp_path, [_vpn(at(0), "dana", "4.4.4.4"), _admin(at(5), "dana", "5.5.5.5")])
    assert actor["users"] == ["dana"]
    assert actor["ips"] == ["4.4.4.4", "5.5.5.5"]
    assert actor["countries"] == ["Japan", "Russia"]


def test_case_differences_are_one_account(tmp_path):
    (actor,) = _actors(tmp_path, [_vpn(at(0), "Dana", "4.4.4.4"), _admin(at(5), "dana", "4.4.4.4")])
    assert len(actor["users"]) == 1 and actor["ips"] == ["4.4.4.4"]


def test_creating_an_account_links_creator_and_account(tmp_path):
    lines = [_sys(at(0), logdesc="Object attribute configured", user="rak", srcip="5.5.5.5",
                  action="Add", msg="Add system.admin back1"),
             _admin(at(5), "back1", "5.5.5.5")]
    (actor,) = _actors(tmp_path, lines)
    assert actor["users"] == ["back1", "rak"]
    assert [c["account"] for c in actor["accounts_created"]] == ["back1"]


def test_failed_logins_link_nothing(tmp_path):
    fails = [_sys(at(i), logdesc="Admin login failed", user=f"guess{i}", srcip="9.9.9.9",
                  action="login", status="failed") for i in range(5)]
    assert _actors(tmp_path, fails) == []


def test_unrelated_accounts_stay_separate(tmp_path):
    actors = _actors(tmp_path, [_vpn(at(0), "a", "1.1.1.1"), _vpn(at(1), "b", "2.2.2.2")])
    assert len(actors) == 2


def test_shared_ip_does_not_merge_accounts(tmp_path):
    lines = [_vpn(at(i), f"user{i}", "7.7.7.7") for i in range(MAX_USERS_PER_IP + 1)]
    actors = _actors(tmp_path, lines)
    assert len(actors) == MAX_USERS_PER_IP + 1 and all(a["ips"] == [] for a in actors)


def test_actor_is_linked_to_its_incident(tmp_path):
    actors = _actors(tmp_path, [_vpn(at(0), "Dana", "4.4.4.4"), _vpn(at(1), "other", "6.6.6.6")])
    now = datetime(2026, 10, 23)
    inc = Incident(incident_id=7, title="t", detections=[], first_seen=now, last_seen=now,
                   entities={"user": ["dana"]})
    links = link_incidents(actors, [inc])
    assert [a["users"] for a in links[7]] == [["Dana"]]
    assert next(a for a in actors if a["users"] == ["Dana"])["incident_ids"] == [7]
    assert next(a for a in actors if a["users"] == ["other"])["incident_ids"] == []
