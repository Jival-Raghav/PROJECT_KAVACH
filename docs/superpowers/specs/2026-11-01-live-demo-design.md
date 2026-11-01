# Kavach Live Mode: design

Date: 2026-11-01 · Branch: `feat/live-demo` (off `feat2/clean`) · PRD item: B-5 "Live mode: new log lines update the attack path within seconds"

## Intent

On demo day we get a new FortiGate dataset of 10–50 GB that we have never seen. It is already on the laptop as a local file and comes from the same network as `firex-10G.log` (same `10.10.x.x` segments). Kavach should start showing results as soon as we point it at the file. It should not make the judges wait 30–60 minutes for a batch run to finish.

As each new slice of the log is processed, every view updates: the incident list, attack path, blast radius, timeline, Devil's Advocate review, report, anomalies, actors, accounts, response plan and control findings. New data may revise earlier results. An incident can gain steps, two incidents can merge, and an early false alarm can disappear once enough history exists.

## Goals

1. **Start from a file path.** The UI has a field where the user types or pastes the path to the log on this laptop, then presses Start. The CLI gets the same thing as a backup for demo day.
2. **Results within about a minute.** The first incidents appear soon after Start. The run keeps refining until the whole file is processed.
3. **Handles 10–50 GB.** Bounded memory (under 8 GB peak, the PRD's "Great" bar). The only extra disk use is compressed Parquet. A full 50 GB pass finishes in under 1 hour.
4. **Survives a crash.** If the process dies or the laptop sleeps, restarting the same run resumes from the last checkpoint instead of starting from zero.
5. **Everything stays current.** After each update cycle, every page and every incident tab shows the latest results without a manual reload.
6. **The story is visible.** A change feed shows what each cycle did: new incidents, incidents that gained steps, merges and withdrawals.

## Non-goals

- Downloading from a URL. The dataset is local.
- Following a log that is still being written (`tail -f`). The input is a finished file.
- Scoring against ground truth for the new dataset, which ships with no labels. Benchmarking stays firex-only.
- Changing detection rules, correlation, scoring or any per-feature logic. Live mode re-runs the existing logic on more data and does not change what it decides.
- A new network map. The dataset is from the same network, so `config/assets.yaml` is reused as is.
- Login, multiple users, or cloud deployment.

## Anti-goals (failure even if it technically works)

- **Breaking the existing firex run or its numbers.** The firex run, `python -m killchain.cli run`, `bench`, and all 173 existing tests must behave exactly as before.
- **A half-written file reaching the UI.** The API must never serve a JSON file while a cycle is writing it. Today's `write_text` is not atomic, which is harmless for batch runs but breaks here.
- **Incident numbers shuffling under the analyst.** If an analyst has incident #13 open and a cycle finishes, #13 must still be the same incident. Today ids are reassigned 1..N by `first_seen` on every run, which would reshuffle them.
- **The UI freezing or erroring mid-run.** For example, an incident that disappears while its page is open.

## Constraints

- Existing stack only: Python 3.12, DuckDB, PyArrow/Parquet, FastAPI, React + Vite. No new services and no new Python dependencies.
- Rules must still contain no dataset IOCs (an existing test enforces this).
- Work happens on `feat/live-demo`. Commits carry only the user's name, with no Claude attribution.
- **No damage to the current setup (user requirement).** Existing pages, tabs, graphs and their behaviour on the firex run stay exactly as they are. Live mode is added around them. It does not rework them.
- **The new UI blends in (user requirement).** The start screen, live bar, run selector and change feed reuse the existing CSS variables, classes (`card`, `kc-*`, chips, pills, tone colours), lucide icons and component patterns from `frontend/src/styles.css` and the current pages. No new styling system, no new UI library, and no visual departure from the existing dark theme.

## How it works (decided)

### 1. Separate runs, firex untouched

Each live run gets its own `run_id` (for example `live-20261101-1432`) and its own directory `backend/data/killchain/runs/<run_id>/`, with the same file layout as firex. Live mode never writes to the existing `firex` run.

The frontend gains a **run selector**: a small control in the top bar listing `firex` and any live runs. Every API call passes the selected `run_id`. All endpoints already accept `run_id`; today the frontend just never sends it.

### 2. Streaming read → Parquet parts

A background **live job** (a thread in the API process, so the UI can watch it):

- Opens the local file and reads it line by line. A raw log is read directly. `.gz` is decompressed on the fly with the standard library.
- Feeds each line through the existing `parse_line` and writes each 200k-line batch as `events/part-NNNNN.parquet`, the same way `ingest_log` does today. Malformed lines are skipped and counted.
- After every part, records a **checkpoint** in `live_state.json`, written atomically: the part number, lines read so far, and the file byte offset where the next part starts.
- Reports progress as bytes read out of the file's size. For `.gz`, progress is the compressed bytes consumed out of the compressed size.
- **Restartable:** starting the same `run_id` again (UI or `cli live --run-id`) reads `live_state.json`, keeps the parts already written, and resumes. A raw file resumes by seeking to the checkpoint byte offset. A `.gz` file re-decompresses from the start and skips the lines already written. Job ownership (the 409 check, the stop signal) is in memory, per process.

The existing `ingest_log` is unchanged.

### 3. Update cycles

A second loop in the live job runs **analysis cycles**:

- A cycle starts as soon as at least one new Parquet part exists and the previous cycle has finished. Cycles never overlap. As the data grows each cycle takes longer, so cycles naturally space out with no extra throttling.
- A cycle runs the **existing post-ingest pipeline** over all parts written so far: clock-stall detection, rules, correlation, scoring, timeline/path/reach/report, anomaly, actors, accounts, review, response and compliance. To make this possible, `run_killchain` is refactored so the part after ingest becomes a reusable `analyse_run(run_dir, …)`. `run_killchain(skip_ingest=…)` keeps its exact current behaviour by calling it.
- Each cycle writes **all** output files atomically (write to a temp file, then `os.replace`). It then bumps a `generation` counter in `live_state.json`.
- A final cycle runs after the last part, and the run is then `complete`.

Because each cycle recomputes everything over all data so far, revisions to earlier results happen automatically. That includes baselines filling in, which removes early "unusual country" false alarms.

### 4. Stable incident numbers

Correlation still produces incidents its own way, but the live job maps each one onto a **persistent incident number** using `incident_registry.json`. That file stores each number's set of `detection_id`s from the last cycle:

- A new incident inherits the old number it shares the **most detection ids** with (on a tie, the lower number). Because the match is on overlap rather than one key, an incident keeps its number when an earlier detection joins it. That happens with late threshold crossings and out-of-order timestamps; firex has 5.3M lines inside a clock stall.
- A new incident that overlaps no old one gets the next unused number.
- If one new incident overlaps several old numbers (a merge), it keeps the **lower** number. The others are recorded as `merged_into`.
- An old number that no new incident overlaps is recorded as `withdrawn`.
- If one old number's detections split across several new incidents, the largest overlap keeps the number and the rest get new numbers.
- `GET /api/incidents/{id}` for a merged id returns `404` with `{"merged_into": N}`, and the UI follows it to N. For a withdrawn id it returns `404` with `{"withdrawn": true}`. The UI then shows "This incident was withdrawn after more data arrived" instead of an error.

The firex batch path keeps its current 1..N numbering, so benchmark output does not change.

### 5. Change feed

After each cycle the job compares the new incident set with the previous one and appends an entry to `changes.jsonl`. Each entry records the cycle number, time, % processed, and lists of `new`, `grew` (with which new steps), `merged` and `withdrawn` incident ids, plus short headline text such as "#7 gained step T1505.003 Web Shell".

### 6. API additions

- `POST /api/live/start` `{path, run_id?}`: checks the path exists and is a readable regular file, then starts the live job. Returns `409` if a live job is already running. Given an existing `run_id` with a checkpoint, it resumes.
- `GET /api/live/status?run_id=` returns `{status: processing|complete|stopped|error, path, bytes_read, bytes_total, lines_read, lines_parsed, lines_skipped, parts, generation, cycle_seconds, last_cycle_at, error?}`.
- `GET /api/live/changes?run_id=&since_generation=` returns change-feed entries.
- `POST /api/live/stop` stops the job cleanly. Results already written stay viewable, and the run can be resumed later.
- `GET /api/runs` lists run ids with their status, for the run selector.

Existing endpoints are unchanged. They only read the run's files, which are now always written whole.

### 7. Frontend

- **Start screen** on the Attack Incidents page, shown when the selected run is empty or the user clicks "New live run": a file-path field, a Start button and a note on accepted formats (FortiGate `.log` or `.gz`).
- **Live bar** across the top while a live run is active: progress (% of file), lines parsed, cycle count, time of last update, and a "Live" indicator.
- **Auto-refresh**: a shared hook polls `/api/live/status` every 2 s. When `generation` changes, every mounted page re-fetches its data: the incident list, the open incident with all its tabs, anomalies, actors, accounts, response plan and control findings.
- **Change feed panel**: the latest cycle summaries, each linking to the affected incident.
- **Incident page resilience**: handles merged incidents (redirect) and withdrawn ones (notice), as in section 4.
- Graph tabs keep the user's zoom and selection across a refresh if the selected node still exists.

### 8. CLI backup

`python -m killchain.cli live --path FILE [--run-id ID]` runs the same live job in the foreground and prints a summary after each cycle. The UI can watch it through the same files. This is the fallback if starting from the browser has trouble on demo day.

## Left to the builder

- The minimum amount of data before the first cycle. Bias toward showing something within about 60 s.
- Whether the heavy context-only stages (anomaly, actors, accounts) are skipped on some cycles if a cycle grows too long. If so, they must always run on the final cycle, and the UI must show when each was last refreshed.
- Visual design of the live bar, start screen and change feed, following the existing styles.
- Whether to parallelise parsing across cores. This is optional and comes after everything else works. Single-thread parsing (~26 MB/s today) means roughly 30+ minutes for 50 GB.

## My calls (not discussed; the user may override)

- **Withdrawn incidents** leave the main list but appear in the change feed, and their page shows a notice. They are not kept as greyed-out rows.
- **Early-results banner**: until 25% of the file is processed, the live bar says results are early and history-based rules (unusual country, anomalies) may still change. History-based rules are not suppressed.
- **Accepted inputs**: a local raw FortiGate log or a `.gz` of one. `.zip` and folders of several files are out of scope.
- **Run selector default**: the UI opens on the most recent live run if one exists, otherwise on `firex`.
- **Incident numbering** matches on detection overlap, as in section 4. This was my answer to the reviewer's concern about numbers shuffling.
