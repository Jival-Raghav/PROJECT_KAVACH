# Third-Party Disclosures & Attribution

This document lists all third-party libraries, machine learning frameworks, models, and datasets utilized by Kavach v2 in compliance with hackathon submission guidelines.

---

## 1. Python Libraries (Backend)

| Library | Version / Spec | License | Purpose |
|---|---|---|---|
| **FastAPI** | `>=0.110.0` | MIT | High-performance asynchronous REST API framework |
| **Uvicorn** | `>=0.28.0` | BSD-3-Clause | ASGI web server implementation |
| **Pydantic** | `>=2.6.0` | MIT | Data parsing, validation, and canonical schema definitions |
| **SQLAlchemy** | `>=2.0.0` | MIT | SQLite persistence for runs, mapping profiles, and audit log |
| **scikit-learn** | `>=1.4.0` | BSD-3-Clause | Isolation Forest anomaly detection and KMeans clustering |
| **NetworkX** | `>=3.2.0` | BSD-3-Clause | Graph modeling for lateral movement & blast radius calculations |
| **pandas** | `>=2.2.0` | BSD-3-Clause | Data ingestion, vectorised profiling, and DSL operations |
| **pyarrow** | `>=15.0.0` | Apache-2.0 | High-performance columnar Parquet dataset caching |
| **RapidFuzz** | `>=3.6.0` | MIT | Fast fuzzy string matching for schema heuristic mapping |
| **ReportLab** | `>=4.1.0` | BSD-like | Automated PDF compliance audit pack generation |
| **Groq SDK** | `>=0.5.0` | Apache-2.0 | Cloud LLM client for rapid testing and evaluation |
| **OpenAI SDK** | `>=1.14.0` | Apache-2.0 | Interface for LM Studio and Ollama local server endpoints |
| **httpx** | `>=0.27.0` | BSD-3-Clause | Asynchronous HTTP requests and Ollama API integration |
| **python-multipart** | `>=0.0.9` | Apache-2.0 | Multi-part form/file upload support for FastAPI |
| **python-dotenv** | `>=1.0.0` | BSD-3-Clause | Environment variable management |
| **PyYAML** | `>=6.0.1` | MIT | Parsing SoD rules, control catalogs, and red-team payloads |
| **pytest** | `>=8.0.0` | MIT | Automated test suite and per-phase acceptance gate execution |
| **Ruff** | `>=0.3.0` | MIT | Extremely fast Python linter and code quality checker |

---

## 2. JavaScript / Node.js Libraries (Frontend)

| Library | Version | License | Purpose |
|---|---|---|---|
| **React** | `^18.3.1` | MIT | Declarative component UI library |
| **React DOM** | `^18.3.1` | MIT | DOM rendering engine for React |
| **React Router DOM** | `^6.29.0` | MIT | Multi-page client-side routing |
| **Vite** | `^5.4.19` | MIT | Next-generation frontend build tool and dev server |
| **Tailwind CSS** | `^3.4.17` | MIT | Utility-first styling for dark command center aesthetic |
| **D3.js** | `^7.9.0` | ISC | Force-directed graphs and interactive scatter plots |
| **Recharts** | `^2.15.3` | MIT | Responsive data visualizations (department bar charts, etc.) |
| **Lucide React** | `^0.513.0` | ISC | Vector iconography for cyber command center |

---

## 3. Large Language Models (LLMs)

| Model Name | Provider / Engine | License | Role in Kavach |
|---|---|---|---|
| **Llama 3.3 70B Versatile** | Groq Cloud API | Llama 3 Community | Primary testing & verification model for Prosecutor, DA, and Adjudicator |
| **Llama 3 8B Instruct** | LM Studio (Local :1234) | Llama 3 Community | Local Prosecutor and Mapper pass |
| **Qwen 2.5 / 3 8B** | Ollama (Local :11434) | Apache-2.0 | Local Devil's Advocate and Guard pass |
| **Deterministic Fallback** | Internal (`StubClient`) | Proprietary / N/A | Full rule-based offline fallback when no LLM is configured |

---

## 4. Datasets & Benchmarks

| Dataset Identifier | Origin | Description | Usage |
|---|---|---|---|
| **Dataset A** | Mitigata Hackathon Provided | Mock identity database (300 users) and access logs (900 events) | Baseline regression and ground-truth evaluation |
| **Dataset B** | Synthetic Generator (`gen_datasets.py`) | Workday-style HR export + Okta-style JSON access events | Multi-source schema autopilot and identity resolution testing |
| **Dataset C** | Synthetic Generator (`gen_datasets.py`) | AWS CloudTrail and IAM access logs with nested structures | Cloud identity schema and blast radius testing |
| **Dataset D** | Synthetic Generator (`gen_datasets.py`) | Stress dataset with noisy headers, missing dates, and unnormalized rows | Fault tolerance and degradation matrix evaluation |
| **Red-Team Suite** | Synthetic Generator (`tests/redteam/`) | 30+ inert prompt injection strings | AI Security layer defense benchmark (ASR evaluation) |
