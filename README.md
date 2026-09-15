# TransOrg AgentIQ Datathon - Track 2: Cybersecurity

This repository contains the end-to-end "Data to Insights" pipeline for Track 2: **Zero-Trust Telemetry & Insider Threat Logs**.

## Overview
Our mission is to detect compromised accounts and insider threats by analyzing massive, noisy network logs and IAM audit trails. This project fulfills all 4 Gates of the Datathon rubric, transitioning raw, messy logs into a cleaned database, an interactive Executive Dashboard, and a Graph-First AI Agent.

---

## 🚀 Live Deployments (Gate 3 & 4)
* **Executive Dashboard:** [View Live Dashboard](https://datathon-e4opafeyjqqdbdxirjygbc.streamlit.app/)
* **AgentIQ AI Chatbot:** [View Live AI Agent](https://datathon-e8veeg6bkxc9k8dbyi7cin.streamlit.app/)

---

## How to Run the Project (Gate 1 Requirement)

### 1. Prerequisites
Ensure you have Python 3.9+ installed. Install the required dependencies:
```bash
pip install pandas numpy openpyxl streamlit plotly python-dotenv groq
```

### 2. Step 1: Data Rescue (Data Engineering)
Run the automated data cleaning pipeline. This script will ingest the raw CSV/JSON/Excel files and output cleaned, structured datasets.
```bash
python data_rescue.py
```
*(Note: The script will print the raw vs. cleaned row counts to the terminal as proof of deduplication and cleaning.)*

### 3. Step 2: Executive Dashboard
Launch the interactive Streamlit SOC dashboard to view KPIs, Trends, and the Geospatial Threat Map.
```bash
streamlit run app.py
```

### 4. Step 3: AgentIQ (Graph-First AI)
To use the AI Agent, you must configure a free Groq API key (to power the NLP routing). 
1. Create a file named exactly `.env` in the root directory.
2. Add your API key to the file:
```env
GROQ_API_KEY=gsk_your_api_key_here
```
3. Launch the agent:
```bash
streamlit run agent.py
```
You can now ask natural language queries like: *"Show the trend of failed login attempts by department."*

### 5. Step 4: Streamlit Cloud Deployment
If you wish to deploy this project yourself on Streamlit Community Cloud:
1. Push this repository to a public GitHub account.
2. Log into [share.streamlit.io](https://share.streamlit.io/) and click **New App**.
3. Point the deployment to `app.py` for the Dashboard, and `agent.py` for the AI Agent.
4. **Important for the Agent:** Before clicking Deploy, go to **Advanced Settings -> Secrets** and input your Groq API key:
```toml
GROQ_API_KEY="gsk_your_api_key_here"
```

---

## Proof of Data Cleaning & Decisions (Gate 2)
As documented in the inline `# DECISION:` comments inside `data_rescue.py`:
- `user_id` was standardized using Regex to strip non-digits, guaranteeing a 1:1 join across IAM and Endpoint systems.
- Mixed timestamps (EU/US/ISO) were standardized into UTC format using robust Pandas parsing.
- String anomalies in firewall rules and department names were forcibly mapped to unified ontologies.
- Invalid IPs were nullified using Regex to prevent geospatial mapping failures.

## Data Dictionary
**cleaned_identity_asset_master.csv**
- `user_id`: Standardized employee identifier (e.g., EMP12345)
- `department`: Normalized department name (e.g., IT, Sales, R&D)
- `hostname`: Assigned device hostname
- `status`: Employee employment status

**cleaned_firewall_logs.csv**
- `timestamp`: Standardized datetime of connection attempt
- `action`: Normalized rule action (`allow`, `deny`)
- `src_ip` / `dst_ip`: Validated IPv4 addresses (invalid coerced to null)
- `bytes_sent` / `bytes_received`: Numeric representation of traffic volume
- `geo_country`: Origin country for geospatial mapping

**cleaned_iam_audit_trail.csv**
- `event_category`: High-level event category (`login_success`, `login_failed`, `other`)
- `risk_score`: Numeric risk score (0-100) extracted from unstructured text
- `mfa_passed`: Boolean state of MFA execution

**cleaned_endpoint_alerts.csv**
- `severity`: Normalized alert severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- `detected_timestamp` / `resolved_timestamp`: Parsed timeline of alert lifecycle
