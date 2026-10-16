# Problem 01: Identity Sprawl & Access Detection (ISPAD)

## Overview
This repository contains the solution for Identity Sprawl & Access Detection (ISPAD). The system identifies, analyzes, and mitigates risks associated with orphaned accounts, excessive privileges, and anomalous user behavior. Rather than relying on rigid rules that generate alert fatigue, this platform employs a hybrid architecture combining machine learning anomaly detection with a unique dual-LLM "Devil's Advocate" reasoning layer to significantly reduce false positives.

## Core Features
1. **Dynamic Risk Scoring**: Integrates Isolation Forest anomaly scoring with deterministic heuristics (like Separation of Duties checks) to grade user risk out of 100.
2. **Behavioral Clustering**: Uses K-Means clustering to map access events into distinct behavioral profiles (e.g., After-Hours Activity, High-Sensitivity Access).
3. **Dual-LLM Narrative Engine**: A two-pass reasoning system where one model acts as the Prosecutor building a case against a user, and a second model acts as a Devil's Advocate to tear that case down based on organizational context.
4. **Cinematic Dashboard**: A high-performance React frontend built with an immersive, dark-themed command center aesthetic, featuring interactive D3.js force-directed graphs for visualizing lateral movement risks.

---

## How to Run the Project

### Prerequisites
- Python 3.10+ (Using a virtual environment or Conda is recommended)
- Node.js & npm (for the frontend)
- Local LLM providers:
  - Ollama (installed locally for the Devil's Advocate pass)
  - LM Studio (installed locally for the Prosecutor pass)

### 1. Start the Local LLM Servers
**Ollama Setup**
Open a terminal and start the Ollama service. Pull your preferred model if you haven't already:
```bash
ollama serve
ollama pull qwen3:8b
```

**LM Studio Setup**
Open the LM Studio application, load a robust instruction-tuned model (e.g., Llama 3 8B Instruct), and click "Start Server" on the Local Server tab. It should default to port 1234.

### 2. Start the Backend API
Navigate to the backend directory, install the dependencies, and start the FastAPI server:
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Note: Ensure the `.env` file in the backend directory is properly configured so `PROSECUTOR_PROVIDER` is set to `lmstudio` and `DA_PROVIDER` is set to `ollama`.

### 3. Start the Frontend Dashboard
In a new terminal window, navigate to the frontend directory, install dependencies, and launch the Vite development server:
```bash
cd frontend
npm install
npm run dev
```
Open your browser and navigate to `http://localhost:5173` to view the dashboard.

---

## ML Architecture & Data Processing

The system uses a layered approach, combining deterministic heuristics, statistical machine learning, and generative AI to surface only high-fidelity alerts.

### Data Processing Pipeline
1. **Ingestion & Validation**: Raw CSVs (`identity_users.csv`, `identity_events.csv`) are ingested and parsed strictly using Pydantic schemas. This ensures type safety, handles null values gracefully, and standardizes timestamps.
2. **Feature Engineering**: The pipeline extracts distinct numerical and categorical features per user based on a historical baseline. Key features include:
   - `after_hours_ratio`: Percentage of events occurring outside 9 AM - 5 PM.
   - `weekend_ratio`: Percentage of events on Saturday or Sunday.
   - `sensitivity_ratio`: Percentage of events targeting high-sensitivity systems.
   - `distinct_systems`: Count of unique systems accessed.
   - `days_inactive`: Delta between the last login and the current simulated date.

### Machine Learning Models Used

**1. Isolation Forest (scikit-learn)**
- **Purpose**: Anomaly Scoring (detecting behavioral outliers).
- **Mechanism**: Rather than profiling normal points, it actively isolates anomalies. By evaluating engineered features (after-hours ratio, cross-department access, stale times), it identifies users whose behavior is statistically isolated from the rest of the company. It generates a raw score that normalizes into a 0-100 `risk_score`.

**2. K-Means Clustering (scikit-learn)**
- **Purpose**: Event Behavioral Clustering.
- **Mechanism**: Events are embedded into a vector space based on the time of day, day of week, resource sensitivity, and success rate. K-Means identifies distinct clusters (e.g., "Normal Business Operations", "High-Sensitivity Access"). Users are assigned to the cluster that dominates their activity, providing immediate behavioral context.

**3. Deterministic Heuristics (Rule-based Models)**
- **Separation of Duties (SoD)**: Matrix checks to prevent conflicts, such as ensuring a user cannot both approve and submit financial invoices.
- **Compliance Engine**: Maps specific behavioral violations to regulatory frameworks (NIST AC-2, AC-6, GDPR Art.32).
- **Departmental Z-Score Analysis**: Calculates the mean risk score per department and flags users whose risk score is more than 2 standard deviations above their peers (surfaced as Org Anomalies).

### The Dual-LLM "Devil's Advocate" Workflow

To solve the industry-wide problem of alert fatigue, we built a dual-LLM reasoning engine:

**Pass 1: The Prosecutor (LM Studio)**
Analyzes the ML output, user metadata, and flagged events to build a structured, evidence-backed accusation highlighting why the user is a security threat.

**Pass 2: The Devil's Advocate (Ollama)**
Critiques the Prosecutor's findings by specifically hunting for mitigating context. For example, it might identify that while a user has a high stale risk, their job title is "Board Member," making their infrequent logins normal rather than suspicious. It outputs a `doubt_score` (0.0 to 1.0) used to adjust the final severity rating.

**Pass 3: Final Inference**
The system feeds both arguments back into the primary model to synthesize a final verdict, generating a clear summary of what happened alongside actionable remediation steps.

---

## Dataset Information

This project includes fabricated sample data for development and testing.

**identity_users.csv (100 user records)**
Comprehensive mock user account database with realistic attributes (job title, department, system access, inactivity days, privilege level) across multiple departments.

**identity_events.csv (300+ access events)**
Access logs showing user activities across systems, including timestamps, actions taken, resource sensitivity, and an anomaly marker for ground-truth evaluation.

### Ground Truth
Anomalies are explicitly marked in the `anomaly_marker` column of the events dataset. These are used to validate the detection models, calculate precision and recall metrics, and understand baseline suspicious behavior.
