import threading

import pytest

from tests.kc_fixture import at, fg_line, write_log
from tests.test_kc_pipeline_eval import RULES, _lines

import killchain.live as live
from killchain.changes import read_changes
from killchain.live import LiveJob, new_state, read_state, save_state
from killchain.pipeline import load_run, run_killchain
from killchain.store import list_parts, open_events

POLL = 0.01
FIRST = 3  # parts the first gated cycle sees


def _log(tmp_path):
    return write_log(tmp_path / "live.log", _lines())


def _titles(run):
    return {inc["title"] for inc in load_run(run).values()}


@pytest.fixture
def gate(monkeypatch):
    """Make the first cycle see exactly parts 0-2 (the port scan), deterministically.

    The reader is held before writing part 3 until the first cycle has run, and the job
    sees no parts until three exist, so every gated test gets >= 2 cycles and the first
    cycle already finds the scan.
    """
    first_cycle = threading.Event()
    real_write, real_list = live._write_part, live.list_parts

    def gated_write(batch, events_dir, part):
        if part >= FIRST:
            assert first_cycle.wait(timeout=30), "first cycle never ran"
        real_write(batch, events_dir, part)

    def gated_list(run_dir):
        parts = real_list(run_dir)
        return parts if first_cycle.is_set() or len(parts) >= FIRST else []

    monkeypatch.setattr(live, "_write_part", gated_write)
    monkeypatch.setattr(live, "list_parts", gated_list)
    return first_cycle


def _batch_titles(tmp_path, log):
    other = tmp_path / "batch"
    run_killchain(log, other, RULES)
    return _titles(other)


def test_live_job_end_to_end_matches_batch(tmp_path, gate):
    log = _log(tmp_path)
    run = tmp_path / "run"
    job = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL,
                  on_cycle=lambda _e: gate.set())
    st = job.run()
    assert st["status"] == "complete"
    assert st["generation"] >= 2
    assert st["finished_at"] and st["error"] is None
    assert read_state(run)["status"] == "complete"
    assert len(list_parts(run)) == 5
    assert _titles(run) == _batch_titles(tmp_path, log)
    changes = read_changes(run)
    assert changes and changes[0]["new"]


def test_incident_numbers_stable_across_cycles(tmp_path, gate):
    log = _log(tmp_path)
    run = tmp_path / "run"
    seen: dict[str, int] = {}

    def on_cycle(_entry):
        for iid, inc in load_run(run).items():
            assert seen.setdefault(inc["title"], iid) == iid
        gate.set()

    st = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL, on_cycle=on_cycle).run()
    assert st["status"] == "complete" and st["generation"] >= 2
    assert seen


def test_stop_and_resume_equals_uninterrupted(tmp_path, gate):
    log = _log(tmp_path)
    run = tmp_path / "run"
    job = None

    def on_cycle(_entry):
        job.stop()
        gate.set()

    job = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL, on_cycle=on_cycle)
    st = job.run()
    assert st["status"] == "stopped"
    assert st["ingest_done"] is False and st["generation"] == 1
    assert read_state(run)["status"] == "stopped"

    st2 = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL).run()
    assert st2["status"] == "complete" and st2["ingest_done"] is True
    assert st2["generation"] >= 2 and st2["error"] is None
    assert _titles(run) == _batch_titles(tmp_path, log)
    con = open_events(run, parts=list_parts(run))
    nos = [r[0] for r in con.execute("select line_no from events_all order by line_no").fetchall()]
    assert nos == list(range(1, 169))


def test_single_part_file_completes(tmp_path):
    log = write_log(tmp_path / "small.log", [fg_line(at(i)) for i in range(5)])
    run = tmp_path / "run"
    st = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL).run()
    assert st["status"] == "complete"
    assert st["generation"] == 1


def test_resume_with_different_path_rejected(tmp_path):
    a = write_log(tmp_path / "a.log", [fg_line(at(0))])
    b = write_log(tmp_path / "b.log", [fg_line(at(0))])
    run = tmp_path / "run"
    save_state(run, new_state(a))
    with pytest.raises(ValueError, match="was started on"):
        LiveJob(run, b, RULES)


def test_start_runs_in_background_and_reader_error_is_recorded(tmp_path, monkeypatch):
    log = _log(tmp_path)
    run = tmp_path / "run"

    def boom(*_a, **_k):
        raise OSError("disk gone")

    monkeypatch.setattr(live, "_write_part", boom)
    job = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL)
    job.start()
    job.join(timeout=30)
    assert not job.is_alive()
    assert job.state["status"] == "error" and job.state["error"] == "disk gone"
    assert read_state(run)["status"] == "error"
    with pytest.raises(OSError, match="disk gone"):
        LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL).run()


def test_cycle_numbers_follow_generation_across_resume(tmp_path, gate):
    log = _log(tmp_path)
    run = tmp_path / "run"
    job = None

    def on_cycle(_entry):
        job.stop()
        gate.set()

    job = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL, on_cycle=on_cycle)
    job.run()
    LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL).run()
    changes = read_changes(run)
    assert [e["cycle"] for e in changes] == [e["generation"] for e in changes]
    assert [e["generation"] for e in changes] == list(range(1, len(changes) + 1))


def test_run_records_owner_and_heartbeat(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(live, "HEARTBEAT_SECONDS", 0.01)
    log = write_log(tmp_path / "small.log", [fg_line(at(i)) for i in range(5)])
    run = tmp_path / "run"
    st = LiveJob(run, log, RULES, batch_size=40, poll_seconds=POLL).run()
    assert st["owner_pid"] == os.getpid() and st["heartbeat_at"]
    assert set(new_state(log)) == set(read_state(run))
