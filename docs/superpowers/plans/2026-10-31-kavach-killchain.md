# Kavach Kill Chain & Attack Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Kavach v2 (branch `main`) so it turns the FortiGate log dump `REAL_10G_DATA/firex-10G.log` into ranked, MITRE-labelled, linked attack incidents with a timeline, an attack-path graph, a "what can they reach next" view, a plain-English report and an API — meeting every Must-have (FR-1…FR-7) and Bonus (B-1…B-4; B-5 deferred) of the PRD, scored against a ground-truth file we derive from the logs.

**Architecture:** A new `backend/killchain/` package sits beside the existing identity pipeline. A line parser streams the log into Parquet parts (bounded memory); DuckDB runs YAML-defined detection rules over those parts; detections are linked into incidents by attacker entities and pivot hosts; incidents are scored, turned into paths/timelines, given a reachability view (reusing `graph/blast.py`) and a report (reusing `llm/client.py` + `security/sanitize.py`). A FastAPI router serves precomputed results; two new React pages render them.

**Tech Stack:** Python 3.12, DuckDB, PyArrow/Parquet, NetworkX, Pydantic v2, FastAPI, PyYAML, pytest; React 18 + Vite + d3 (already in `frontend/package.json`).

**Spec:** `hackathonDOCS/PRD_Kill_Chain_Attack_Path.pdf` (PRD), plus the dataset facts and recovered ground truth in the "Dataset facts" section below (the PRD ships no labels for our file).

## Global Constraints

- Work on `main` only; ignore `origin/test1`.
- Must-haves FR-1…FR-7 and bonuses B-1…B-4 are in scope; B-5 (live mode) is Task 14, executed only after Tasks 1–13 are green.
- PRD targets (report every one in `reports/killchain_benchmark.md`): Detection > 70% good / > 90% great; Correct labels > 60% / > 85%; Attack path half / all; False alarms < 30% / < 10%; Processing time < 3 hours / < 1 hour; Memory < 16 GB / < 8 GB; Investigation speed < 2 seconds / < 500 ms.
- FR-1: never load the full log into memory; ingestion holds at most one batch (default 200,000 lines) in Python memory; DuckDB `memory_limit` set to `'4GB'`.
- Detection rules live in `config/detection_rules/*.yaml` and **must not contain any IOC from the ground truth** (no external IPs, usernames, domains, or hostnames from the data). Internal ranges `10.0.0.0/8` style CIDRs are allowed. Enforced by a test (Task 5).
- Every detection carries an ATT&CK technique id that exists in `config/mitre_techniques.yaml`, plus that file's tactic and kill-chain stage.
- Timestamps: use `eventtime` (nanoseconds since epoch, UTC) as the canonical `ts`; display strings are ISO-8601 UTC with `Z`.
- Tests are flat files `tests/test_kc_*.py`; imports are relative to `backend/` (`from killchain.parse import parse_line`), matching `pyproject.toml` `pythonpath = ["backend"]`.
- Ruff: line length 100, rules E/F/W (`pyproject.toml`). Existing 96 tests must stay green.
- Large outputs go to `backend/data/killchain/` (gitignored); never commit Parquet or the log.

## Dataset facts (established 2026-10-31, file already cleaned)

- `REAL_10G_DATA/firex-10G.log` was truncated to its last complete line: **4,815,675,121 bytes, 9,125,382 lines**, `2026-10-23 08:48:26` → `2026-10-30 08:48:25` (+0530), one device `FGT60FTK00000000`. The 1.7 GB random-byte tail was removed. Treat any further malformed line as skip-and-count.
- Format: FortiOS `key=value` pairs separated by spaces; values are bare or double-quoted (quoted values contain spaces, `(`, `=`, `%`).
- Mix: traffic/forward 64%, event/system 15% (1,272,524 "Admin login failed" — background noise), utm webfilter/dns/app-ctrl/ips/virus, event vpn/ha/sdwan/dhcp/connector.
- Network: internal `10.10.{10,20,30,40,50,99}.0/24`; `srcintfrole`/`dstintfrole` ∈ {lan, dmz, wan}; `10.10.20.0/24` is DMZ (servers); `10.10.99.1` is the firewall management IP.
- **Noise traps** (must NOT become incidents): 20 IPS signatures at ~7k hits each spread uniformly (incl. `Mirai.Botnet.Command.Traffic`), ~135k blocked viruses with random destinations, ~41k webfilter blocks, 1.27M failed admin logins from ~350 IPs (~3,600 each, `reason="name_invalid"`), single large flows up to ~9 MB with random pairs.
- Planted lines alone carry the field `crscore` (550 lines) — useful for verifying ground truth only; **rules must not use `crscore`** (too dataset-specific; enforced in Task 5's IOC test).

### Recovered ground truth (18 scenarios, 22 steps)

Times are local (+0530). "×N" is the event count each step selector must return in Task 2.

| GT | Scenario | Step(s) → acceptable techniques (primary first) | Selector essentials | ×N |
|---|---|---|---|---|
| 01 | XSS against DMZ portal | T1190 | ips, src 178.50.251.250 → 10.10.20.20, 10-23 16:22–16:31 | 60 |
| 02 | Mirai C2 fan-in from IoT segment | T1071 | ips, src 10.10.40.0/24 → 154.35.54.115:23, 10-23 20:36–21:16 | 60 |
| 03 | Malware download burst (`invoice_2026.pdf.exe`) | T1105, T1204.002, T1036.007 | virus, 10.10.10.51 → 111.253.167.34, 10-24 06:31–06:46 | 12 |
| 04 | Admin login from unusual country (parul.sinha, Türkiye) | T1078 | logdesc "Admin login successful", user parul.sinha | 1 |
| 05 | DNS tunnelling to `*.doqotobitum.com` | T1071.004, T1048.003 | dns, src 10.10.10.88, hostname LIKE '%doqotobitum.com' | 1500 |
| 06 | SQL injection on DMZ | T1190 | ips, src 131.228.119.59 → 10.10.20.20 | 220 |
| 07 | Dropper not blocked (Nemucod via duckdns) | T1204.002, T1105 | virus, action detected, src 10.10.10.118 | 3 |
| 08 | Low-and-slow exfiltration | T1041, T1030, T1048 | traffic, 10.10.20.31 → 7.93.184.183, 10-26 → 10-29 | 2000 |
| 09 | Command injection on DMZ | T1190, T1059 | ips, src 72.7.116.239 → 10.10.20.20 | 55 |
| 10 | Webshell access on DMZ | T1505.003 | webfilter, src 202.36.226.247 → 10.10.20.20 | 120 |
| 11 | SMB fan-out to DMZ servers | T1021.002 | traffic, 10.10.10.44 → 10.10.20.0/24 port 445 | 2400 |
| 12 | External port scan | T1595, T1595.001, T1046 | traffic deny, src 194.102.163.167 | 1024 |
| 13 | Admin login from Russia (Deepika.Khan) | T1078 | logdesc "Admin login successful", user Deepika.Khan | 3 |
| 14 | VPN impossible travel (keerat.ghughal, US vs Türkiye) | T1133, T1078 | vpn, user keerat.ghughal, srcip 9.222.114.167 | 2 |
| 15 | Path traversal on DMZ | T1190, T1083 | ips, src 72.90.113.105 → 10.10.20.20 | 80 |
| 16 | SQLi → webshell, same attacker | step 1 T1190; step 2 T1505.003 | src 32.127.48.11: ips (10-29 02:07) then webfilter (02:41–03:01) | 60, 40 |
| 17 | Rogue admin `svc_backup30` | 1 T1136.001; 2 T1078; 3 T1070 | src 203.228.177.117: "Add system.admin" 03:55 → login svc_backup30 04:02 → "Delete system.admin" 04:07 | 1, 1, 1 |
| 18 | Logging & firewall tampering (Tejas.Roy) | 1 T1562.001; 2 T1562.004 | "Attribute configured": log-disk msgs (16:31, 20:36); "firewall policy were purged" (18:28) | 2, 1 |

Uncertain linkages deliberately kept separate (document in benchmark report): GT-01/GT-18 overlap at 16:31; GT-08's source 10.10.20.31 is also an SMB target in GT-11 but exfil starts a day earlier.

## Review Focus

1. Malformed or partial lines (e.g. a truncated final line, binary junk) → skipped and counted, ingestion never raises. Test in Task 1.
2. Quoted values with spaces, `=` and `%`-encoding (`msg="... from https(1.2.3.4) ..."`, `url="/x?a=%3D"`) → parsed intact, no key bleeding. Test in Task 1.
3. A shared victim (DMZ host attacked by several unrelated external IPs) → stays as separate incidents, not one mega-incident. Test in Task 6.
4. Uniform background alerts (same IPS signature from many random pairs; many failed logins with no success) → zero incidents. Test in Task 5.
5. Unknown incident id or a run that has not been executed → HTTP 404 / empty list, never 500. Test in Task 11.

---

## File Structure

```
backend/killchain/
  __init__.py
  models.py        # Pydantic: IngestStats, Detection, Incident, PathGraph, TimelineStep, ReachResult, Metrics
  parse.py         # parse_line(), FIELDS, column types
  ingest.py        # ingest_log(): streaming → Parquet parts
  store.py         # open_events(): DuckDB view over Parquet
  mitre.py         # technique catalogue loader / labeller
  rules.py         # Rule model, YAML loader, SQL compiler, run_rules()
  correlate.py     # detections → incidents
  scoring.py       # incident risk score (B-1)
  pathgraph.py     # timeline + host/user graph per incident (FR-5)
  reach.py         # "what next" reachability (FR-6)
  report.py        # plain-English report (B-2)
  groundtruth.py   # GT loader + step resolution
  evaluate.py      # PRD metrics
  pipeline.py      # run_killchain(): orchestration + persistence
  cli.py           # `python -m killchain.cli run|bench`
  live.py          # B-5 (Task 14, deferred)
backend/api/incidents.py          # FR-7 router
config/detection_rules/fortigate.yaml
config/mitre_techniques.yaml
config/assets.yaml
data/ground_truth/firex_planted.yaml
scripts/bench_killchain.py
reports/killchain_benchmark.md   # generated
frontend/src/pages/KillChain.jsx
frontend/src/pages/IncidentDetail.jsx
tests/kc_fixture.py               # synthetic FortiGate line builder
tests/test_kc_*.py
Dockerfile, frontend/Dockerfile, docker-compose.yml
```

---

### Task 1: Environment, parser and streaming ingest (FR-1)

**Files:**
- Create: `backend/killchain/__init__.py`, `backend/killchain/models.py`, `backend/killchain/parse.py`, `backend/killchain/ingest.py`, `backend/killchain/store.py`, `tests/kc_fixture.py`, `tests/test_kc_parse_ingest.py`
- Modify: `requirements.txt` (add `duckdb>=1.1.0`), `.gitignore` (add `backend/data/killchain/`), `backend/config.py` (add settings below)

**Interfaces:**
- Produces:
  - `parse.FIELDS: list[tuple[str, str]]` — `(column, arrow_type)` for: `line_no:int64, ts:timestamp[ns, UTC], logid, type, subtype, level, action, srcip, srcport:int64, srcintf, srcintfrole, dstip, dstport:int64, dstintf, dstintfrole, proto:int64, service, policyid:int64, sessionid:int64, srccountry, dstcountry, sentbyte:int64, rcvdbyte:int64, duration:int64, app, appcat, apprisk, logdesc, msg, user, ui, method, status, reason, hostname, url, catdesc, attack, attackid:int64, severity, virus, crscore:int64, extra` (untyped = string; `extra` = JSON of unknown keys).
  - `parse.parse_line(line: str, line_no: int) -> dict | None` — `None` for malformed lines (not starting with `date=`, no `eventtime`, or undecodable).
  - `models.IngestStats(lines_read: int, lines_parsed: int, lines_skipped: int, parts: int, seconds: float, peak_rss_mb: float)`
  - `ingest.ingest_log(log_path: Path, out_dir: Path, batch_size: int = 200_000) -> IngestStats` — writes `out_dir/events/part-00000.parquet`…
  - `store.open_events(run_dir: Path) -> duckdb.DuckDBPyConnection` — connection with view `events` over `run_dir/events/*.parquet`, `SET memory_limit='4GB'`.
  - `tests/kc_fixture.py`: `fg_line(**fields) -> str` (fills header defaults `date,time,eventtime,tz,devname,devid,logid,type,subtype,level,vd`; quotes string values), `write_log(path: Path, lines: list[str]) -> Path`, `ingest_lines(tmp_path, lines) -> Path` (returns run_dir after ingest), `REPO: Path` (repo root).
  - `config.Settings`: `KILLCHAIN_LOG_PATH` (default `<root>/REAL_10G_DATA/firex-10G.log`), `KILLCHAIN_DATA_DIR` (default `backend/data/killchain`), `KILLCHAIN_RULES_DIR` (`config/detection_rules`), `KILLCHAIN_MITRE_PATH` (`config/mitre_techniques.yaml`), `KILLCHAIN_ASSETS_PATH` (`config/assets.yaml`), `KILLCHAIN_GT_PATH` (`data/ground_truth/firex_planted.yaml`).

- [ ] **Step 1: Create venv and record baseline**

Run: `python3.12 -m venv .venv && source .venv/bin/activate && pip install -r backend/requirements.txt -r requirements.txt duckdb && pytest -q`
Expected: `96 passed` (record the actual number in the commit message if different).

- [ ] **Step 2: Write failing tests** in `tests/test_kc_parse_ingest.py`

```python
def test_parse_quoted_values_with_spaces_and_equals():
    line = ('date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" '
            'logid="0100032002" type="event" subtype="system" level="alert" '
            'msg="Administrator admin login failed from https(209.50.167.232) because x=y" '
            'url="/a?b=%3D1" srcip=209.50.167.232 dstport=443')
    r = parse_line(line, 7)
    assert r["msg"] == "Administrator admin login failed from https(209.50.167.232) because x=y"
    assert r["url"] == "/a?b=%3D1"
    assert r["srcip"] == "209.50.167.232" and r["dstport"] == 443 and r["line_no"] == 7
    assert r["ts"] == 1792745306564464000  # ns UTC

def test_parse_unknown_key_goes_to_extra():
    r = parse_line(fg_line(type="traffic", subtype="forward", foo="bar"), 1)
    assert json.loads(r["extra"]) == {"foo": "bar"}

def test_parse_rejects_malformed():
    assert parse_line("\x8b\x1f garbage", 1) is None
    assert parse_line('date=2026-10-23 time=08:48:26 type="traffic"', 2) is None  # no eventtime

def test_ingest_skips_bad_lines_and_batches(tmp_path):
    lines = [fg_line(type="traffic", subtype="forward", srcip=f"10.10.10.{i}") for i in range(25)]
    lines.insert(10, "binary\x00junk")
    stats = ingest_log(write_log(tmp_path / "x.log", lines), tmp_path / "run", batch_size=10)
    assert (stats.lines_read, stats.lines_parsed, stats.lines_skipped, stats.parts) == (26, 25, 1, 3)
    con = open_events(tmp_path / "run")
    assert con.execute("select count(*), max(line_no) from events").fetchone() == (25, 26)

def test_ingest_handles_truncated_last_line(tmp_path):
    p = tmp_path / "t.log"
    p.write_bytes((fg_line(type="traffic") + "\n").encode() + b'date=2026-10-30 time=08:48:25 type="tr')
    assert ingest_log(p, tmp_path / "run").lines_skipped == 1
```

- [ ] **Step 3: Run to verify failure** — `pytest tests/test_kc_parse_ingest.py -v` → FAIL (`ModuleNotFoundError: killchain`).

- [ ] **Step 4: Implement** `parse_line` with regex `(?:^| )(\w+)=("(?:[^"\\]|\\.)*"|\S*)`, strip quotes, cast typed columns (bad int → `None`); `ingest_log` reads the file in binary line by line (decode UTF-8 per line, `errors="strict"` → skip on error), accumulates a dict-of-lists batch, writes each batch with `pyarrow.parquet.write_table` using a fixed schema built from `FIELDS`; peak RSS via `resource.getrusage(RUSAGE_SELF).ru_maxrss` (bytes on macOS, KB on Linux — normalise to MB).

- [ ] **Step 5: Run tests** — `pytest tests/test_kc_parse_ingest.py -v` → PASS; `pytest -q` → all previous tests still pass.

- [ ] **Step 6: Ingest the real file once**

Run: `cd backend && python -c "from pathlib import Path; from killchain.ingest import ingest_log; print(ingest_log(Path('../REAL_10G_DATA/firex-10G.log'), Path('data/killchain/runs/firex')))"`
Expected: `lines_read=9125382 lines_parsed=9125382 lines_skipped=0`, `peak_rss_mb` < 2000. Record seconds.

- [ ] **Step 7: Commit** — `git add requirements.txt .gitignore backend/config.py backend/killchain tests/kc_fixture.py tests/test_kc_parse_ingest.py && git commit -m "feat(killchain): streaming FortiGate parser and Parquet ingest (FR-1)"`

---

### Task 2: Ground-truth file and resolver

**Files:**
- Create: `data/ground_truth/firex_planted.yaml`, `backend/killchain/groundtruth.py`, `tests/test_kc_groundtruth.py`

**Interfaces:**
- Consumes: `store.open_events`.
- Produces:
  - YAML shape:
    ```yaml
    dataset: firex-10G.log
    derived_by: manual hunt 2026-10-31 (see plan "Dataset facts")
    scenarios:
      - id: GT-16
        name: SQLi then webshell from one attacker
        steps:
          - id: GT-16-1
            techniques: [T1190]
            where: "subtype='ips' AND srcip='32.127.48.11'"
            expected_count: 60
          - id: GT-16-2
            techniques: [T1505.003]
            where: "subtype='webfilter' AND srcip='32.127.48.11'"
            expected_count: 40
    ```
  - `groundtruth.GTStep(id: str, techniques: list[str], where: str, expected_count: int)`, `GTScenario(id: str, name: str, steps: list[GTStep])`
  - `groundtruth.load_ground_truth(path: Path) -> list[GTScenario]`
  - `groundtruth.resolve_steps(con, scenarios) -> dict[str, set[int]]` — step id → set of `line_no`.

- [ ] **Step 1: Write failing tests**

```python
def test_resolve_steps_on_fixture(tmp_path):
    run = ingest_lines(tmp_path, [fg_line(type="utm", subtype="ips", srcip="1.2.3.4"),
                                  fg_line(type="utm", subtype="ips", srcip="5.6.7.8")])
    gt = tmp_path / "gt.yaml"
    gt.write_text("scenarios:\n- id: S\n  name: s\n  steps:\n  - id: S-1\n"
                  "    techniques: [T1190]\n    where: \"srcip='1.2.3.4'\"\n    expected_count: 1\n")
    steps = resolve_steps(open_events(run), load_ground_truth(gt))
    assert steps == {"S-1": {1}}

def test_real_ground_truth_shape():
    sc = load_ground_truth(REPO / "data/ground_truth/firex_planted.yaml")
    assert len(sc) == 18 and sum(len(s.steps) for s in sc) == 22
    assert all(s.steps and all(st.techniques for st in s.steps) for s in sc)
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** loader (pydantic) and resolver (`SELECT line_no FROM events WHERE <where>` per step). Write all 18 scenarios / 22 steps from the "Recovered ground truth" table, with `where` clauses pinned by IP/user/time (`ts BETWEEN TIMESTAMP '...' AND ...` in UTC = local − 5:30) and `expected_count` = the ×N column.

- [ ] **Step 4: Verify against real data**

Run: `cd backend && python -m killchain.groundtruth --check ../data/ground_truth/firex_planted.yaml data/killchain/runs/firex` (add a `__main__` that prints `step id, resolved count, expected_count, OK/MISMATCH`).
Expected: every line `OK`. If any mismatches, inspect with DuckDB and correct the selector or the count (a mismatch is a GT bug, not a code bug). Also run a residual hunt and paste results into the YAML header comment: `SELECT srcip,dstip,dstport,count(*) FROM events WHERE srcip LIKE '10.%' AND dstip LIKE '10.%' AND NOT (srcip='10.10.10.44' AND dstport=445) GROUP BY ALL ORDER BY 4 DESC LIMIT 20` — if any non-noise cluster appears, add a scenario.

- [ ] **Step 5: Run tests** → PASS. **Step 6: Commit** — `feat(killchain): recovered ground truth for firex dataset`

---

### Task 3: Domain models and MITRE catalogue

**Files:**
- Create: `config/mitre_techniques.yaml`, `backend/killchain/mitre.py`, `tests/test_kc_mitre.py`
- Modify: `backend/killchain/models.py`

**Interfaces:**
- Produces:
  - `config/mitre_techniques.yaml`: `techniques: {T1190: {name: "Exploit Public-Facing Application", tactic: initial-access, stage: Exploitation}, ...}` for exactly: T1595, T1595.001, T1046, T1190, T1059, T1083, T1505.003, T1105, T1204.002, T1036.007, T1071, T1071.004, T1048, T1048.003, T1041, T1030, T1021.002, T1078, T1133, T1110, T1136.001, T1098, T1070, T1562.001, T1562.004. `stage` ∈ Lockheed kill chain: `Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives`. Also `stage_order: [..7 stages in order..]`.
  - `mitre.TechniqueLabel(id: str, name: str, tactic: str, stage: str, stage_index: int)`
  - `mitre.load_catalogue(path: Path | None = None) -> dict[str, TechniqueLabel]` (cached), `mitre.label(technique_id: str) -> TechniqueLabel` (raises `KeyError` for unknown ids).
  - `models.Detection(detection_id: str, rule_id: str, title: str, technique: TechniqueLabel, severity: Literal["low","medium","high","critical"], first_seen: datetime, last_seen: datetime, event_count: int, sample_line_nos: list[int], entities: dict[str, list[str]], outcome: Literal["allowed","blocked","mixed"], summary: str)` — entity keys are `src_ip`, `dst_ip`, `user`, `domain`; `sample_line_nos` capped at 50 (full list goes to Parquet in Task 4).
  - `models.Incident(incident_id: int, title: str, detections: list[Detection], first_seen: datetime, last_seen: datetime, entities: dict[str, list[str]], tactics: list[str], stages: list[str], raw_alert_count: int, risk_score: float = 0.0, severity: str = "low")`

- [ ] **Step 1: Failing tests** — `test_label_known`: `label("T1110")` → `tactic == "credential-access"`, `stage == "Actions on Objectives"`; `test_label_unknown_raises`; `test_catalogue_covers_ground_truth`: every technique in `firex_planted.yaml` is in the catalogue; `test_stage_index_order`: `label("T1595").stage_index < label("T1190").stage_index < label("T1071").stage_index < label("T1041").stage_index`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): MITRE ATT&CK catalogue and domain models (FR-3)`

---

### Task 4: Config-driven rule engine (FR-2, B-4)

**Files:**
- Create: `backend/killchain/rules.py`, `tests/test_kc_rules_engine.py`

**Interfaces:**
- Consumes: `store.open_events`, `mitre.label`, `models.Detection`.
- Produces:
  - Rule YAML (one file may hold many rules under `rules:`):
    ```yaml
    - id: KC-NET-001
      title: Port scan from one source
      technique: T1595.001
      severity: medium
      kind: threshold            # match | threshold | rare_for_entity | sequence
      where: "type='traffic' AND action='deny' AND srcintfrole='wan'"   # SQL over `events`
      selection: {}              # optional Sigma-style alternative/addition to `where`
      group_by: [srcip]
      window_minutes: 10         # gap-based session: new session when gap > window
      min_count: 100
      distinct: {field: dstport, min: 50}
      entities: {src_ip: srcip, dst_ip: dstip}
      # rare_for_entity only:
      baseline_where: "subtype='vpn' AND action='ssl-login'"
      key: user
      value: srccountry
      max_share: 0.01            # fire if value's share in key's baseline < max_share (missing baseline ⇒ fire)
      # sequence only:
      then_where: "logdesc='Admin login successful'"
      join_on: srcip
      then_within_minutes: 60
    ```
  - `selection` modifiers (Sigma-style): `field: value` (=), `field: [a, b]` (IN), `field|contains`, `field|startswith`, `field|endswith`, `field|re`, `field|gte`, `field|lte`; combined with `where` by AND. Values are bound as parameters, not string-interpolated.
  - `rules.Rule` (pydantic model of the above), `rules.load_rules(rules_dir: Path) -> list[Rule]` (validates `technique` via `mitre.label`, rejects unknown `kind`), `rules.compile_rule(rule: Rule) -> tuple[str, list]` (SQL + params), `rules.run_rules(con, rules: list[Rule]) -> list[Detection]`, which also writes table `detection_events(detection_id VARCHAR, line_no BIGINT)` into `con`.
  - `detection_id` = `f"{rule.id}:{sha1(group values + session start)[:10]}"` (deterministic across runs).
  - `outcome`: `blocked` if every event's action ∈ {deny, blocked, dropped}, `allowed` if none, else `mixed`.

Threshold SQL shape (gap sessions), the one algorithm the signature does not fix:
```sql
WITH m AS (SELECT * FROM events WHERE <where>),
s AS (SELECT *, CASE WHEN lag(ts) OVER w IS NULL OR ts - lag(ts) OVER w > INTERVAL <window> MINUTE
                     THEN 1 ELSE 0 END AS brk
      FROM m WINDOW w AS (PARTITION BY <group_by> ORDER BY ts)),
t AS (SELECT *, sum(brk) OVER (PARTITION BY <group_by> ORDER BY ts ROWS UNBOUNDED PRECEDING) AS sess FROM s)
SELECT <group_by>, sess, count(*) n, count(DISTINCT <distinct.field>) d, min(ts), max(ts), list(line_no)
FROM t GROUP BY <group_by>, sess HAVING n >= <min_count> AND d >= <distinct.min>
```

- [ ] **Step 1: Failing tests** (fixture lines via `fg_line`, rules written to `tmp_path`):
  - `test_match_rule_emits_one_detection_per_group` — 3 `virus action=detected` lines from 2 sources, `kind: match, group_by: [srcip]` → 2 detections, event counts {2,1}.
  - `test_threshold_gap_session_splits` — 120 deny lines from one srcip over 120 distinct ports within 5 min, then 120 more 3 hours later; `window_minutes: 10, min_count: 100` → 2 detections.
  - `test_threshold_distinct_filter` — 150 denies to the same port → 0 detections with `distinct: {field: dstport, min: 50}`.
  - `test_rare_for_entity` — user A: 99 VPN logins from "Japan" + 1 admin success from "Russia" → 1 detection; user B: admin success from its usual country → 0; user C with no baseline → 1.
  - `test_sequence` — 60 failed admin logins from 9.9.9.9 then a success from 9.9.9.9 within 10 min → 1 detection with technique from the rule (`T1110`); 60 failures without success → 0.
  - `test_selection_sigma_modifiers` — `selection: {attack|startswith: "HTTP.", dstintfrole: dmz}` compiles to parameterised SQL and matches only the intended row.
  - `test_detection_events_table` — after `run_rules`, `select count(*) from detection_events` equals the sum of `event_count`.
  - `test_unknown_technique_rejected` — `load_rules` raises `ValueError` for `technique: T9999`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): YAML/Sigma-style rule engine on DuckDB (FR-2, B-4)`

---

### Task 5: FortiGate detection rule pack + accuracy tuning

**Files:**
- Create: `config/detection_rules/fortigate.yaml`, `tests/test_kc_rule_pack.py`

**Interfaces:**
- Consumes: Task 4 rule schema; Task 2 GT.
- Produces: the rule pack below. Thresholds are starting values; tune only via YAML in Step 5.

| id | title | kind | technique | essentials |
|---|---|---|---|---|
| KC-RECON-001 | External port scan | threshold | T1595.001 | traffic deny, `srcintfrole='wan'`; group srcip; 10 min; distinct dstport ≥ 100 |
| KC-RECON-002 | Internal port scan | threshold | T1046 | same, `srcintfrole IN ('lan','dmz')` |
| KC-WEB-001 | Web exploit burst against DMZ | threshold | T1190 | ips, `srcintfrole='wan' AND dstintfrole='dmz' AND attack LIKE 'HTTP.%'`; group srcip,dstip; 30 min; min 10 |
| KC-WEB-002 | Webshell request on DMZ | threshold | T1505.003 | webfilter, wan→dmz, `regexp_matches(url, '\.(php|aspx|jsp)$')` and path in upload/tmp/well-known/wp-content; group srcip,dstip; 60 min; min 5 |
| KC-C2-001 | Many internal hosts → one external IP flagged by IPS | threshold | T1071 | ips, `srcintfrole IN ('lan','dmz') AND dstintfrole='wan'`; group dstip; 60 min; distinct srcip ≥ 10 |
| KC-C2-002 | DNS tunnelling | threshold | T1071.004 | dns, `length(split_part(hostname,'.',1)) >= 30`; group srcip, `regexp_extract(hostname,'([^.]+\.[^.]+)$',1)`; 30 min; min 50 |
| KC-MAL-001 | Malware download burst | threshold | T1105 | virus; group srcip,dstip; 30 min; distinct virus ≥ 3 |
| KC-MAL-002 | Malware detected but not blocked | match | T1204.002 | virus, `action='detected'`; group srcip |
| KC-EXF-001 | Repeated outbound transfer to one external host | threshold | T1041 | traffic accept, lan/dmz→wan; group srcip,dstip; 720 min; min 200 |
| KC-LAT-001 | SMB fan-out to internal hosts | threshold | T1021.002 | traffic, src and dst internal (`srcip LIKE '10.%' AND dstip LIKE '10.%'`), dstport 445; group srcip; 120 min; distinct dstip ≥ 10 |
| KC-ID-001 | Admin login from unusual country | rare_for_entity | T1078 | `logdesc='Admin login successful'`; baseline VPN ssl-login by user; value srccountry; max_share 0.01 |
| KC-ID-002 | VPN login from unusual country | rare_for_entity | T1133 | vpn with user; baseline = same; value srccountry; max_share 0.01 |
| KC-ID-003 | Brute force then success | sequence | T1110 | first: "Admin login failed" min 50 per srcip; then: "Admin login successful"; join srcip; 60 min |
| KC-PER-001 | Admin account created | match | T1136.001 | `logdesc='Object attribute configured' AND msg LIKE 'Add system.admin%'`; group srcip |
| KC-PER-002 | Admin account deleted | match | T1070 | same with `'Delete system.admin%'` |
| KC-DEF-001 | Logging disabled/changed | match | T1562.001 | `logdesc='Attribute configured' AND msg ILIKE '%log%setting%'`; group user |
| KC-DEF-002 | Firewall policies purged | match | T1562.004 | `logdesc='Attribute configured' AND msg ILIKE '%firewall policy%purged%'`; group user |

- [ ] **Step 1: Failing tests**
  - `test_rule_pack_has_no_iocs` — collect every quoted literal in each GT `where` (IPs, users, domains) plus the token `crscore`; assert none appears in any file under `config/detection_rules/`.
  - `test_every_rule_fires_on_its_pattern` — parametrised over rule ids: build a minimal fixture per rule (e.g. 120 wan denies over 120 ports for KC-RECON-001) → ≥ 1 detection from that rule.
  - `test_noise_produces_no_detections` — fixture of: 500 IPS `Mirai.Botnet.Command.Traffic` lines each with a distinct random src/dst pair; 2,000 failed admin logins from 40 IPs and no success; 300 blocked viruses with random destinations; 50 single 9 MB flows to random IPs → `run_rules` returns `[]`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Write the YAML.** **Step 4: Run** → PASS.
- [ ] **Step 5: Tune on real data**

Run (add to `killchain/evaluate.py` in Task 10 later; for now an ad-hoc script): run all rules on `data/killchain/runs/firex`, then per GT step print `covered? (any detection_events line_no ∈ step lines)`, plus every detection not intersecting any GT step (false positives) grouped by rule.
Expected: 22/22 steps covered and 0 non-GT detections. Adjust thresholds in YAML only (never add IOCs) until met; record the before/after numbers in the commit message.

- [ ] **Step 6: Commit** — `feat(killchain): FortiGate detection rule pack mapped to ATT&CK`

---

### Task 6: Correlation into incidents (FR-4, B-3)

**Files:**
- Create: `backend/killchain/correlate.py`, `tests/test_kc_correlate.py`

**Interfaces:**
- Consumes: `models.Detection`, `models.Incident`.
- Produces: `correlate.correlate(detections: list[Detection], strong_gap_hours: float = 72, pivot_gap_hours: float = 24, internal_prefixes: tuple[str, ...] = ("10.",)) -> list[Incident]` — incident ids are 1..N ordered by `first_seen`; `raw_alert_count` = sum of member `event_count` (B-3); `tactics`/`stages` ordered by `stage_index`; `title` = title of the member detection with the highest `stage_index`, prefixed by the attacker entity.

Linking rules (union-find over detections):
1. **Strong link** — share an attacker-side entity (an external `src_ip`, i.e. not starting with an internal prefix, or a `user`) and their time intervals are ≤ `strong_gap_hours` apart.
2. **Pivot link** — internal host H is a `dst_ip` of detection A and a `src_ip` of detection B, `B.first_seen >= A.first_seen`, and `B.first_seen - A.last_seen <= pivot_gap_hours`.
3. Never link on a shared victim alone (two external attackers hitting the same DMZ host stay separate).

- [ ] **Step 1: Failing tests**
  - `test_shared_victim_not_merged` — two KC-WEB-001 detections from different external IPs on the same `dst_ip`, 2 hours apart → 2 incidents.
  - `test_same_attacker_merged_in_order` — SQLi then webshell from the same external IP 30 min apart → 1 incident; `tactics == ["initial-access", "persistence"]`.
  - `test_admin_chain_by_src_ip` — create-admin, login (user `svc_x`), delete-admin from one IP within 15 min → 1 incident with 3 detections and `raw_alert_count == 3`.
  - `test_pivot_link_requires_order` — A: external → 10.0.0.5 at t0; B: 10.0.0.5 → external at t0+1h → merged; same B at t0−1d → not merged.
  - `test_strong_gap_limit` — same external IP, 5 days apart → 2 incidents.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): link detections into incidents by attacker and pivot (FR-4, B-3)`

---

### Task 7: Risk score (B-1) and attack path / timeline (FR-5)

**Files:**
- Create: `backend/killchain/scoring.py`, `backend/killchain/pathgraph.py`, `tests/test_kc_score_path.py`
- Modify: `backend/killchain/models.py` (add `TimelineStep`, `PathGraph`)

**Interfaces:**
- Produces:
  - `scoring.score_incident(inc: Incident) -> tuple[float, str]` — 0–100 and severity (`critical` ≥ 80, `high` ≥ 60, `medium` ≥ 40, else `low`). Score = 35·(max stage_index / 6) + 20·(distinct tactics / 4, capped 1) + 20·(1 if any detection `outcome != "blocked"` else 0) + 15·max severity weight (low 0.25, medium 0.5, high 0.75, critical 1) + 10·min(1, log10(raw_alert_count)/4). Round to 1 decimal.
  - `scoring.rank(incidents: list[Incident]) -> list[Incident]` — sets `risk_score`/`severity`, sorts descending (ties → earlier `first_seen` first).
  - `models.TimelineStep(ts: datetime, technique_id: str, technique_name: str, tactic: str, stage: str, description: str, detection_id: str, event_count: int)`
  - `models.PathGraph(nodes: list[dict], edges: list[dict])` — node `{id, label, kind: "external_ip"|"host"|"user"|"firewall"|"domain", segment: str|None}`; edge `{source, target, technique_id, ts, label}`.
  - `pathgraph.build_timeline(inc: Incident) -> list[TimelineStep]` — one step per detection, sorted by `first_seen`.
  - `pathgraph.build_path(inc: Incident, firewall_ip: str = "10.10.99.1") -> PathGraph` — edge per detection from attacker entity → victim entity (`src_ip→dst_ip`; user-based detections: `user→firewall`; DNS: `host→domain`); node ids prefixed by kind (`host:10.10.20.20`).
- [ ] **Step 1: Failing tests** — `test_score_progression_beats_volume`: incident with a blocked 1,024-event scan scores lower than one with allowed create-admin + login + delete (3 events); `test_rank_sorted_desc`; `test_timeline_sorted`; `test_path_admin_chain_edges`: rogue-admin incident yields nodes `{external_ip:…, user:svc_x, firewall:10.10.99.1}` and 3 edges ordered by `ts`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): incident risk score and attack-path graph/timeline (B-1, FR-5)`

---

### Task 8: "What can the attacker reach next" (FR-6)

**Files:**
- Create: `config/assets.yaml`, `backend/killchain/reach.py`, `tests/test_kc_reach.py`
- Modify: `backend/killchain/models.py` (add `ReachTarget`, `ReachResult`)

**Interfaces:**
- Consumes: `graph.blast.compute_blast_radius(g, start_node, max_depth)` (existing; expects nodes with `node_type` ∈ {system, resource} and `sensitivity`).
- Produces:
  - `config/assets.yaml`:
    ```yaml
    firewall_mgmt_ip: 10.10.99.1
    segments:
      - {cidr: 10.10.10.0/24, name: Corp LAN 1, sensitivity: medium}
      - {cidr: 10.10.20.0/24, name: DMZ servers, sensitivity: high}
      - {cidr: 10.10.30.0/24, name: Corp LAN 3, sensitivity: medium}
      - {cidr: 10.10.40.0/24, name: IoT / devices, sensitivity: low}
      - {cidr: 10.10.50.0/24, name: Corp LAN 5, sensitivity: medium}
      - {cidr: 10.10.99.0/24, name: Management, sensitivity: crown}
    ```
  - `reach.build_network_graph(con, assets: dict) -> nx.DiGraph` — nodes `system:<ip>` for internal hosts seen as src or dst of accepted traffic (sensitivity from segment), `system:firewall` (crown); edges from **observed** accepted internal→internal flows (`basis="observed"`, attr `ports`), plus `system:firewall → system:<segment-gateway>` for every segment (`basis="admin_control"`). Built once per run with one aggregate SQL (`GROUP BY srcip, dstip`) and cached to `run_dir/netgraph.gpickle`.
  - `models.ReachTarget(node: str, label: str, segment: str, sensitivity: str, hops: int, basis: Literal["observed","same_segment","admin_control"])`, `models.ReachResult(incident_id: int, footholds: list[str], targets: list[ReachTarget], summary: str)`
  - `reach.next_reach(inc: Incident, g: nx.DiGraph, assets: dict, max_depth: int = 2) -> ReachResult` — footholds: internal victim hosts whose detection outcome ≠ blocked, internal sources of malicious activity, and `system:firewall` if any detection is a successful admin login / admin config change. Targets: union of `compute_blast_radius` reachable systems from each foothold plus same-segment hosts (`basis="same_segment"`, hops 1). Sort by sensitivity (crown > high > medium > low) then hops. `summary` like `"Admin control of the firewall: can change policy for 6 segments (412 hosts), including Management."`
- [ ] **Step 1: Failing tests** — `test_admin_incident_reaches_all_segments`; `test_host_foothold_uses_observed_edges` (graph with 10.0.0.5 →445→ 10.0.1.7 gives target `10.0.1.7` basis `observed`); `test_blocked_only_incident_has_no_footholds` (a blocked external scan → `targets == []`, summary says nothing reachable).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): next-reach analysis from footholds (FR-6)`

---

### Task 9: Plain-English incident report (B-2)

**Files:**
- Create: `backend/killchain/report.py`, `tests/test_kc_report.py`

**Interfaces:**
- Consumes: `Incident`, `build_timeline`, `ReachResult`; `llm.client.get_adjudicator_client()`; `security.sanitize.sanitize_text`; `config.get_settings().LLM_REPLAY_ONLY`.
- Produces: `report.render_report(inc: Incident, timeline: list[TimelineStep], reach: ReachResult, use_llm: bool = False) -> dict` with keys `headline: str`, `body_markdown: str`, `generated_by: "template" | "llm"`. Template body sections: *What happened* (one sentence per timeline step: time, technique name + id, entities), *Kill-chain stages reached*, *Alerts merged* (B-3 count), *What they can reach next* (`reach.summary` + top 5 targets), *Recommended actions* (per stage: block external IP, disable account, isolate host, restore logging). With `use_llm=True` and a non-stub provider, send sanitized template text to the LLM asking for a concise rewrite; on any exception or replay-only mode, return the template with `generated_by="template"`.
- [ ] **Step 1: Failing tests** — `test_template_report_mentions_every_step` (each technique id from the timeline appears in `body_markdown`); `test_llm_failure_falls_back` (monkeypatch client to raise → `generated_by == "template"`); `test_report_sanitizes_entities` (an injected `msg` containing `![x](http://evil)` doesn't appear verbatim).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): plain-English incident report with LLM rewrite (B-2)`

---

### Task 10: Pipeline, persistence, evaluation and benchmark

**Files:**
- Create: `backend/killchain/pipeline.py`, `backend/killchain/evaluate.py`, `backend/killchain/cli.py`, `scripts/bench_killchain.py`, `tests/test_kc_pipeline_eval.py`
- Generated (committed): `reports/killchain_benchmark.md`, `reports/killchain_benchmark.json`
- Modify: `backend/killchain/models.py` (add `Metrics`)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `pipeline.run_killchain(log_path: Path, run_dir: Path, rules_dir: Path, skip_ingest: bool = False) -> dict` — ingest (unless `skip_ingest` and parts exist) → rules → correlate → rank → per incident timeline/path/reach/template report → writes `run_dir/incidents.json` (list of incidents with `timeline`, `path`, `reach`, `report`), `run_dir/detection_events.parquet`, `run_dir/run_meta.json` (`IngestStats`, per-stage seconds, peak RSS MB, rule count, detection count, incident count). Returns run_meta.
  - `pipeline.load_run(run_dir: Path) -> dict[int, dict]` — incident id → incident JSON (cached in-process by `run_meta.json` mtime).
  - `models.Metrics(detection_rate, label_accuracy, label_accuracy_lenient, paths_rebuilt, paths_total, false_alarm_rate, processing_seconds, peak_memory_mb, p95_open_ms, per_step: list[dict])`
  - `evaluate.evaluate(run_dir: Path, gt_path: Path) -> Metrics` — step **found** if any detection's lines intersect the step's lines; **label correct** if that detection's technique == `techniques[0]` (strict) or ∈ `techniques` (lenient); scenario **path rebuilt** if one incident contains detections covering all its steps and their `first_seen` order matches step order; **false alarm** = incident with no line in any GT step / all incidents; `p95_open_ms` = p95 over 100 timed `load_run` + lookups of random incident ids.
  - CLI: `python -m killchain.cli run [--log PATH] [--run-id firex] [--skip-ingest]` and `python -m killchain.cli bench [--run-id firex]` (bench writes both report files with a table of every PRD target and Good/Great rating).
- [ ] **Step 1: Failing tests** — end-to-end on a fixture log with two planted mini-scenarios (scan; SQLi→webshell) plus noise and a matching mini GT: `test_pipeline_writes_outputs`; `test_evaluate_perfect_fixture` → `detection_rate == 1.0`, `paths_rebuilt == paths_total == 2`, `false_alarm_rate == 0.0`; `test_evaluate_counts_false_alarm` (add an extra planted-but-not-in-GT pattern → `false_alarm_rate == 1/3`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Full run + benchmark on real data**

Run: `cd backend && python -m killchain.cli run --skip-ingest && python -m killchain.cli bench`
Expected (gate): detection ≥ 0.90, strict labels ≥ 0.85, paths 18/18, false alarms ≤ 0.10, processing < 1 hour, peak memory < 8 GB, p95 open < 500 ms. If a gate fails, return to Task 5 Step 5 (rule YAML) or Task 6 gap parameters, never to IOC-specific code. Also run a cold full run without `--skip-ingest` once and record total time.

- [ ] **Step 6: Commit** — `feat(killchain): pipeline, evaluator and PRD benchmark report`

---

### Task 11: API (FR-7)

**Files:**
- Create: `backend/api/incidents.py`, `tests/test_kc_api.py`
- Modify: `backend/main.py` (include router)

**Interfaces:**
- Consumes: `pipeline.load_run`, `pipeline.run_killchain`, `rules.load_rules`, `report.render_report`.
- Produces (router prefix `/api`, tag `Kill Chain`; run dir = `KILLCHAIN_DATA_DIR/runs/<run_id>`, `run_id` query param default `firex`):
  - `GET /api/incidents?limit=50&min_risk=0` → `[{incident_id, title, risk_score, severity, first_seen, last_seen, tactics, stages, raw_alert_count, detection_count, entities}]` sorted by risk.
  - `GET /api/incidents/{id}` → full incident JSON.
  - `GET /api/incidents/{id}/path` → `{timeline, path}`.
  - `GET /api/incidents/{id}/next` → `ReachResult`.
  - `GET /api/incidents/{id}/report?llm=false` → report dict (LLM only when `llm=true`).
  - `GET /api/killchain/rules` → loaded rules (id, title, technique, kind, severity).
  - `POST /api/killchain/run` → starts `run_killchain` in a background thread; `409` if one is running. `GET /api/killchain/status` → `{status, stage, run_meta}`.
- [ ] **Step 1: Failing tests** (FastAPI `TestClient`, run dir pointed at a `tmp_path` built from the Task 10 fixture via monkeypatched setting): `test_list_sorted_by_risk`; `test_path_endpoint_shape` (keys `timeline`, `path.nodes`, `path.edges`); `test_unknown_incident_404`; `test_no_run_returns_empty_list` (missing run dir → `200 []`); `test_open_latency` (second call to `/api/incidents/1/path` < 500 ms).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `pytest -q` all green.
- [ ] **Step 5: Commit** — `feat(api): kill-chain incidents API (FR-7)`

---

### Task 12: Frontend — incident board and investigation page

**Files:**
- Create: `frontend/src/pages/KillChain.jsx`, `frontend/src/pages/IncidentDetail.jsx`
- Modify: `frontend/src/api.js` (add `getIncidents, getIncident, getIncidentPath, getIncidentNext, getIncidentReport, runKillchain, getKillchainStatus, getKillchainRules`), `frontend/src/App.jsx` (new first nav group `Kill Chain` with items `incidents` "Attack Incidents" and `rules` "Detection Rules"; clicking an incident opens `IncidentDetail`)

**Interfaces:**
- Consumes: Task 11 endpoints (Vite already proxies `/api`).
- Produces:
  - `KillChain.jsx`: run button + status; table of incidents (risk badge, title, kill-chain stage strip across the 7 Lockheed stages with reached stages filled, tactics chips, "N alerts merged", first/last seen).
  - `IncidentDetail.jsx`: header (risk, severity, merged alerts); **Timeline** (vertical list from `timeline`); **Attack path graph** (d3 force layout from `path`, node colour by kind, edge label = technique id, arrows in time order); **Reach next** panel (`summary` + targets table with basis badge); **Report** panel (markdown; "Rewrite with AI" button calls `?llm=true`).
  - Rules page: read-only table of `/api/killchain/rules` with a note that rules live in `config/detection_rules/*.yaml`.
- [ ] **Step 1: Implement** pages following existing patterns in `pages/GraphView.jsx` (d3) and `components/RiskTable.jsx` (table styling, CSS variables in `styles.css`).
- [ ] **Step 2: Verify build** — `cd frontend && npm install && npm run build` → exit 0, no errors.
- [ ] **Step 3: Verify in the running app** — `./run.sh`, open http://localhost:5173 → Kill Chain → incidents list shows ≥ 18 rows topped by the highest risk; open GT-17's incident: timeline shows T1136.001 → T1078 → T1070, graph shows external IP → svc_backup30 → firewall, reach summary mentions Management. Take a screenshot for the README.
- [ ] **Step 4: Commit** — `feat(frontend): kill-chain incident board and investigation view`

---

### Task 13: README, judge run path, Docker Compose

**Files:**
- Create: `Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml`, `docs/KILLCHAIN.md`
- Modify: `README.md` (new top section "Kill Chain & Attack Path (Hackathon PRD)"), `run.sh` (add `--killchain` flag that runs `python -m killchain.cli run` before launch), `Makefile` (add POSIX targets `killchain`, `bench`)

**Interfaces:**
- Produces: README section with: 3-command quick start; where to put the log (`REAL_10G_DATA/`); the PRD requirement → feature → endpoint/file table (FR-1…FR-7, B-1…B-4); the benchmark table copied from `reports/killchain_benchmark.md`; "Add a detection rule" walkthrough editing `config/detection_rules/fortigate.yaml`; honest limits (ground truth recovered by us; dataset was truncated; B-5 status). `docker-compose.yml`: `backend` (python:3.12-slim, mounts `./REAL_10G_DATA` read-only and `./backend/data`, port 8000), `frontend` (node:20, `npm run dev -- --host`, port 5173).
- [ ] **Step 1: Write docs and compose files.**
- [ ] **Step 2: Verify** — `docker compose up --build` then `curl -s localhost:8000/api/incidents | head -c 300` → JSON list (after `POST /api/killchain/run` completes). If Docker is unavailable locally, verify `./run.sh --killchain` instead and note it.
- [ ] **Step 3: Commit** — `docs: kill-chain README, judge quick start, docker compose`

---

### Task 14 (deferred until 1–13 are green): Live mode (B-5)

**Files:**
- Create: `backend/killchain/live.py`, `tests/test_kc_live.py`
- Modify: `backend/api/incidents.py` (`GET /api/killchain/live/stream` SSE), `frontend/src/pages/KillChain.jsx` (live toggle)

**Interfaces:**
- Produces: `live.follow(log_path: Path, run_dir: Path, poll_seconds: float = 2.0, stop: threading.Event | None = None) -> None` — remembers byte offset in `run_dir/live_offset`, parses new complete lines with `parse_line`, appends them as a new Parquet part every poll, re-runs rules limited to `ts >= max(ts) - INTERVAL (max window_minutes of all rules) MINUTE`, merges new detections into incidents with `correlate`, rewrites `incidents.json`, and emits an SSE event `{"updated_incident_ids": [...]}`.
- [ ] **Step 1: Failing test** — `test_live_append_creates_incident_within_seconds`: start `follow` in a thread on a fixture log, append 120 wan deny lines (scan), assert within 5 s `load_run` contains a KC-RECON-001 incident.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(killchain): live tail mode (B-5)`
