# Problem 01: Identity Sprawl & Access Detection - Sample Datasets

## Overview
This folder contains sample/mock data for Problem Statement 01. All data is fabricated and represents a **sample** for development/testing purposes.

## Files Included

### 1. `identity_users.csv` (100 user records)
**Comprehensive mock user account database** with realistic attributes across multiple departments.

**Columns:**
- `user_id` - Unique identifier
- `username` - Login name
- `email` - Email address
- `department` - Which department (Finance, IT, HR, etc.)
- `job_title` - Role
- `privilege_level` - user, power-user, admin
- `systems_access` - Pipe-separated list of allowed systems
- `privileged_roles` - Admin-level roles if any
- `last_login` - When they last accessed anything
- `days_inactive` - How many days since last login
- `is_active` - Currently active employee?
- `hired_date` - When they joined
- `role_change_date` - When their role changed (if applicable)

**Anomalies to Look For:**
- USR-0004 (sarah.brown): Stale account (45 days inactive) but still has HR_Admin privileges
- USR-0017 (andrew.clark): Contractor with 147 days inactive - should be revoked
- USR-0009 (james.martinez): Inactive user (59 days)

### 2. `identity_events.csv` (300+ access events)
**Comprehensive access logs** showing user activities across systems with 35% anomaly density.

**Columns:**
- `timestamp` - When the activity happened
- `user_id` - Who did it
- `username` - Name
- `action` - What they did (login, sql_query, admin_operation, etc.)
- `resource` - What they accessed
- `resource_sensitivity` - Classification (low, medium, high)
- `status` - success or failure
- `source_ip` - Where they accessed from
- `time_classification` - business_hours, unusual_hours, night, week end
- `anomaly_marker` - Label indicating what's suspicious (for evaluation)

**Anomalies Embedded:**
- `STALE_ACCOUNT_LOGIN`: USR-0004 accessing HRIS despite being inactive 45 days
- `AFTER_HOURS_ADMIN_LOGIN`: USR-0005 (admin) logging in at 22:47
- `OFF_HOURS_DB_ACCESS`: USR-0008 accessing sensitive Customer_PII at 00:22
- `PRIVILEGE_CHANGE_OFF_HOURS`: Admin modifying IAM policies at night
- `CROSS_DEPARTMENT_ACCESS`: USR-0003 (Finance Analyst) accessing GL_System (unusual)

## How to Use These Datasets

### Load in Python:
```python
import pandas as pd

# Load users
users = pd.read_csv('identity_users.csv')
print(f"Total users: {len(users)}")
print(f"Active users: {users[users['is_active']==True].shape[0]}")

# Load events
events = pd.read_csv('identity_events.csv')
print(f"Total events: {len(events)}")
print(f"Date range: {events['timestamp'].min()} to {events['timestamp'].max()}")

# Merge for enriched view
events['user_detail'] = events['user_id'].map(users.set_index('user_id')['department'])
```

### Analysis Ideas:
1. **Stale Account Detection**: Who hasn't logged in for 30+ days but still has privileges?
2. **After-Hours Activity**: Who's accessing high-risk systems outside 9-5?
3. **Cross-Dept Access**: Who accesses systems outside their department?
4. **Privilege vs Activity**: Do admin accounts match their roles?
5. **Anomaly Scoring**: Combine multiple signals into a risk score

## Data Characteristics

- **Records**: 20 users, 50 events (sample size for demo)
- **Time Range**: April 15-17, 2026 (3 days)
- **Anomaly Ratio**: ~20% of events contain marked anomalies
- **Systems**: 10+ different systems (ERP, SIEM, Databases, cloud platforms)
- **Privileges**: Mix of user, power-user, and admin accounts

## Real-World Scale

For production:
- Expected Users: 2,000-10,000
- Expected Events: 500,000+ over 90 days
- This sample is 1% of realistic data volume

## Ground Truth

Anomalies are marked in `anomaly_marker` column. Use these to:
1. Validate your detection models
2. Calculate precision/recall metrics
3. Understand what constitutes "suspicious"

## Next Steps

1. **Explore the data** - Understand distributions, patterns
2. **Identify more anomalies** - Beyond the marked ones
3. **Build detection model** - Test anomaly detection algorithms
4. **Create dashboard** - Visualize findings
5. **Document approach** - Explain your methodology

---

**Questions?** See [PARTICIPANT_GUIDE.md](../../PARTICIPANT_GUIDE.md)

---

## 🚀 How to Run the Project

### Prerequisites
- Python 3.10+ (via Conda environment `ispad` recommended)
- Node.js & npm (for the frontend)
- [Ollama](https://ollama.com/) (installed locally for the Devil's Advocate pass)
- [LM Studio](https://lmstudio.ai/) (installed locally for the Prosecutor pass)

### 1. Start the Local LLM Servers
1. **Ollama**: Open a terminal and run:
   ```bash
   ollama serve
   ollama pull qwen3:8b  # or llama3.2, mistral, etc.
   ```
2. **LM Studio**: Open the LM Studio app, load your preferred chat model (e.g., Llama 3 8B Instruct), and click **Start Server** on the "Local Server" tab (default port 1234).

### 2. Start the Backend API
```bash
cd backend
pip install -r requirements.txt  # Or use your conda environment
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
*Note: Ensure the `.env` file in the root directory is properly configured to point `PROSECUTOR_PROVIDER` to `lmstudio` and `DA_PROVIDER` to `ollama`.*

### 3. Start the Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open your browser to `http://localhost:5173` to view the dashboard.

---

## 🧠 ML Architecture & Data Processing

The system uses a hybrid approach combining deterministic heuristics, statistical anomaly detection (ML), and a novel two-pass LLM reasoning layer to drastically reduce false positives.

### Data Processing Pipeline
1. **Ingestion & Validation**: Raw CSVs (`identity_users.csv`, `identity_events.csv`) are ingested and parsed strictly using Pydantic schemas to ensure typing, handle nulls, and standardise timestamps to UTC.
2. **Feature Engineering**: We extract 17 distinct numerical and categorical features per user based on a 365-day historical baseline. This includes:
   - `after_hours_ratio`: Percentage of events occurring outside 9 AM - 5 PM.
   - `weekend_ratio`: Percentage of events on Saturday/Sunday.
   - `sensitivity_ratio`: Percentage of events targeting high-sensitivity systems.
   - `distinct_systems`: Count of unique systems accessed.
   - `days_inactive`: Delta between the last login and the current simulated date.

### Machine Learning Models Used

1. **Isolation Forest (`scikit-learn`)**
   - **What it's for**: Anomaly Scoring (detecting behavioral outliers).
   - **How it works**: It isolates anomalies instead of profiling normal points. By feeding it the engineered features (after-hours ratio, cross-department access, stale times), it identifies users whose behavior is statistically "isolated" from the rest of the company. It generates a raw score that we normalize into a 0-100 `risk_score`.

2. **K-Means Clustering (`scikit-learn`)**
   - **What it's for**: Event Behavioral Clustering.
   - **How it works**: Events are embedded into a vector space based on the time of day, day of week, resource sensitivity, and success rate. K-Means identifies 4 distinct clusters (e.g., "Normal Business Operations", "High-Sensitivity Access", "After-Hours Activity", "Failed Login Spikes"). Users are then assigned to the cluster that dominates their activity, providing immediate behavioral context.

3. **Deterministic Heuristics (Rule-based Models)**
   - **Separation of Duties (SoD)**: Hard-coded matrix checks to prevent conflicts (e.g., a user cannot both approve and submit invoices).
   - **Compliance Engine**: Maps specific behavioral violations to regulatory frameworks (NIST AC-2, AC-6, GDPR Art.32).
   - **Departmental Z-Score Analysis**: Calculates the mean risk score per department and flags users whose risk score is > 2 standard deviations above their peers (Org Anomalies).

### The Two-Pass LLM "Devil's Advocate" Workflow

To solve the "Alert Fatigue" problem (high false positives), we built a dual-LLM reasoning engine:
- **Pass 1: The Prosecutor (LM Studio)**: Analyzes the ML output, user metadata, and flagged events to build a structured, evidence-backed accusation highlighting why the user is a threat.
- **Pass 2: The Devil's Advocate (Ollama)**: Critiques the Prosecutor's findings by specifically hunting for mitigating context (e.g., "This user has a high stale risk, but they are marked as the CTO — they likely delegate tasks and don't log in often. This is a false positive."). It outputs a `doubt_score` (0.0 to 1.0) which is used to adjust the final severity rating.
