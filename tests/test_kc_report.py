import pytest

import killchain.report as report
from tests.test_kc_correlate import det
from killchain.correlate import correlate
from killchain.pathgraph import build_timeline
from killchain.reach import ReachResult
from killchain.report import render_report


def _incident():
    ds = [det("W:1", "T1190", 0, n=60, src_ip="1.1.1.1", dst_ip="10.10.20.20"),
          det("S:1", "T1505.003", 1, n=40, src_ip="1.1.1.1", dst_ip="10.10.20.20")]
    (inc,) = correlate(ds)
    return inc


def _reach(inc):
    return ReachResult(incident_id=inc.incident_id, footholds=["10.10.20.20"], targets=[],
                       summary="From 1 compromised host(s), 0 hosts are reachable.")


@pytest.fixture
def live_llm(monkeypatch):
    from config import get_settings

    monkeypatch.setattr(get_settings(), "LLM_REPLAY_ONLY", False)


def test_template_report_mentions_every_step():
    inc = _incident()
    r = render_report(inc, build_timeline(inc), _reach(inc))
    assert r["generated_by"] == "template"
    for tid in ("T1190", "T1505.003"):
        assert tid in r["body_markdown"]
    assert "100 raw alerts" in r["body_markdown"]
    assert "1.1.1.1" in r["headline"]
    assert "## What they can reach next" in r["body_markdown"]


def test_llm_failure_falls_back(monkeypatch, live_llm):
    class Boom:
        def chat(self, *a, **k):
            raise RuntimeError("provider down")

    monkeypatch.setattr(report, "get_adjudicator_client", lambda: Boom())
    inc = _incident()
    r = render_report(inc, build_timeline(inc), _reach(inc), use_llm=True)
    assert r["generated_by"] == "template"


def test_llm_rewrite_used_and_sanitized(monkeypatch, live_llm):
    class Ok:
        def chat(self, messages, **k):
            assert "T1190" in messages[-1]["content"]
            return "Rewritten story ![img](http://evil.example/x.png)"

    monkeypatch.setattr(report, "get_adjudicator_client", lambda: Ok())
    inc = _incident()
    r = render_report(inc, build_timeline(inc), _reach(inc), use_llm=True)
    assert r["generated_by"] == "llm"
    assert r["body_markdown"].startswith("Rewritten story") and "evil.example" not in r["body_markdown"]


def test_report_sanitizes_entities():
    inc = _incident()
    inc.detections[0].summary = "probe ![x](http://evil.example/p.png) <script>alert(1)</script>"
    r = render_report(inc, build_timeline(inc), _reach(inc))
    assert "evil.example" not in r["body_markdown"] and "<script>" not in r["body_markdown"]
