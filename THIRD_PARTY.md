# Third-Party Disclosures & Attribution

Third-party libraries, models and data used by Kavach.

## Python libraries

| Library | Version | License | Purpose |
|---|---|---|---|
| **FastAPI** | `>=0.110.0` | MIT | REST API |
| **Uvicorn** | `>=0.28.0` | BSD-3-Clause | API server |
| **Pydantic** | `>=2.6.0` | MIT | Data models and validation |
| **DuckDB** | `>=1.1.0` | MIT | SQL detection rules over Parquet |
| **pyarrow** | `>=15.0.0` | Apache-2.0 | Parquet storage for ingested logs |
| **pandas** | `>=2.2.0` | BSD-3-Clause | Entity feature tables |
| **NumPy** | `>=1.26.0` | BSD-3-Clause | Anomaly score calculations |
| **scikit-learn** | `>=1.4.0` | BSD-3-Clause | Isolation Forest anomaly scores |
| **NetworkX** | `>=3.2.0` | BSD-3-Clause | Reachability and actor graphs |
| **Groq SDK** | `>=0.5.0` | Apache-2.0 | Cloud LLM client |
| **OpenAI SDK** | `>=1.14.0` | Apache-2.0 | Client for LM Studio and Ollama local servers |
| **python-dotenv** | `>=1.0.0` | BSD-3-Clause | Environment configuration |
| **PyYAML** | `>=6.0.1` | MIT | Rules, catalogues and test payloads |
| **pytz** | `>=2024.1` | MIT | Time zone support for DuckDB timestamps |
| **pytest** | `>=8.0.0` | MIT | Tests |
| **httpx** | `>=0.27.0` | BSD-3-Clause | API test client |
| **Ruff** | `>=0.3.0` | MIT | Linter |

## JavaScript libraries

| Library | Version | License | Purpose |
|---|---|---|---|
| **React**, **React DOM** | `^18.3.1` | MIT | UI |
| **Vite** | `^5.4.19` | MIT | Build tool and dev server |
| **Tailwind CSS** | `^3.4.17` | MIT | Styling |
| **D3.js** | `^7.9.0` | ISC | Attack-path graph |
| **Lucide React** | `^0.513.0` | ISC | Icons |

## LLMs (optional)

Kavach runs without an LLM, using built-in templates. If configured, it can call:

| Provider | Default model | Role |
|---|---|---|
| **Groq** | Set by `GROQ_MODEL` | Incident review and report rewrite |
| **LM Studio**, **Ollama** | Local model you choose | Same, without sending data off the machine |

## Data

| Item | Origin | Use |
|---|---|---|
| **`firex-10G.log`** | Supplied by the hackathon organisers; not stored in this repo | Input |
| **`data/ground_truth/firex_planted.yaml`** | Recovered by the Kavach team from the log | Benchmark |
| **`tests/redteam/payloads.yaml`** | Written by the Kavach team; inert test strings | Prompt-injection test |
| **MITRE ATT&CK technique names and ids** | MITRE | Labels in `config/mitre_techniques.yaml` |
