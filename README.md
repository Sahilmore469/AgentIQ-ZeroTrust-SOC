# TransOrg AgentIQ Datathon - Track 2: Cybersecurity
## Zero-Trust Telemetry & Insider Threat Command Center

This repository contains the enterprise-grade "Data to Insights" pipeline for Track 2: **Zero-Trust Telemetry & Insider Threat Logs**.

---

## 1. Executive Summary & Architecture Overview

Our mission is to detect compromised accounts, lateral movement, and insider threats across massive, noisy network logs, IAM audit trails, and EDR telemetry. 

Rather than treating datasets as isolated silos or merging them into an unmanageable flat file, we implemented a **Star-Schema-inspired analytical architecture** with cross-system correlation, explainable multi-signal risk scoring, and a multi-view Security Operations Command Center.

### Target Data Architecture

```
                         DIM_IDENTITY_ASSET (user_id, hostname_norm, dept, role, status)
                                |
                 +--------------+--------------+
                 |              |              |
                 ↓              ↓              ↓
             FACT_IAM     FACT_ENDPOINT   FACT_FIREWALL
          (event_id,     (alert_id,       (log_id,
           user_id,       user_id,         hostname_norm,
           hostname_norm, hostname_norm,   session_id,
           session_id,    severity,        action,
           event_category,status,          threat_flag,
           risk_score,    alert_name,      bytes_sent/rec,
           timestamp)     timestamp)       timestamp)
                 |              |              |
                 +--------------+--------------+
                                |
                    CROSS-SYSTEM CORRELATION
           (Session matching + Hostname & Temporal Proximity)
                                |
                 CENTRALIZED ANALYTICAL LAYER
                 (Clean queries, aggregations, KPIs)
                                |
                 BUSINESS LOGIC & RISK SCORING
                 (Explainable rules, 0-100 score, Low/Med/High/Crit)
                                |
             COMMAND CENTER DASHBOARD (Multi-View UI)
```

---

## 2. Intended Track 2 Data Relationships & Join Diagnostics

As specified in `track2_dataset_notes.txt`, the data model implements the following verified relationships:

| Source Dataset | Target Dataset | Join Key(s) | Business Question Enabled | Match Rate | Cardinality Guarantee |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **IAM Audit Trail** | **Identity Master** | `user_id` | Who is performing authentication actions? Department & identity status context. | **100.0%** (20,000 / 20,000) | Exact 1:1 on `user_id` (0 duplicates, 0 row multiplication) |
| **Endpoint Alerts** | **Identity Master** | `user_id` & `hostname_norm` | Which employee and asset triggered the malware or EDR alert? | **100.0%** (user) / **87.96%** (host) | Verified foreign keys with no dropped rows |
| **Firewall Logs** | **Identity Master** | `hostname_norm` | Associate network traffic, blocked connections, and threat flags with assets. | **88.88%** (26,665 / 30,000) | Normalized hostnames (stripped `.corp.local`, normalized casing & separators) |
| **IAM Audit Trail** | **Firewall Logs** | `session_id_norm` & Host Proximity | Did an authentication event correlate with perimeter blocked traffic? | **333 exact session matches**, **hundreds within 30m window** | Defensible temporal correlation |

### Timestamp & Hostname Normalization Rationale
- **Unix Epoch Timestamp Recovery**: Raw telemetry in IAM and Firewall logs contained numeric Unix timestamps (e.g. `1787085290` = August 18, 2026 UTC). A custom parser in `transformations.py` converts these cleanly to UTC, preserving critical date ranges without data loss.
- **Hostname Standardizer**: Normalized variants like `VDR-11307.corp.local`, `lpt-12718`, and `LPT_12621` into canonical uppercase hostnames (e.g. `LPT-12621`), dramatically boosting join match rates from ~54% to ~89%.

---

## 3. Cross-System Correlation Engine

Located in `correlation.py`, the engine implements two explainable correlation methods:
1. **Session-Level Correlation**: Joins IAM audit events and Firewall logs on normalized `session_id_norm` to detect instances where user login sessions coincide with perimeter connection attempts.
2. **Host & Temporal Proximity Correlation**: Uses `pd.merge_asof` to link IAM authentication attempts with Firewall events occurring on the **same host** within a calibrated **30-minute window** ($\pm 1800\text{ s}$).

---

## 4. Explainable Multi-Signal Risk Scoring

Located in `risk_scoring.py`, our analytical scoring engine calculates a normalized **0–100 Risk Score** combining 4 distinct security vectors:
- **Identity Component (30%)**: Number of failed logins, MFA failures, and IAM risk score.
- **Endpoint Component (30%)**: Critical EDR alerts (e.g. Ransomware, Trojan) and High-severity alerts.
- **Network Component (20%)**: Volume of perimeter Firewall denies and threat flags on the host.
- **Cross-System Correlation Component (20%)**: Multi-vector threat signals (e.g. user with simultaneous authentication failures and endpoint alerts, or activity from terminated accounts).

### Risk Classification
- **CRITICAL**: $\ge 80.0$
- **HIGH**: $60.0 - 79.9$
- **MEDIUM**: $35.0 - 59.9$
- **LOW**: $< 35.0$

### Explainability
Every high-risk entity is assigned a human-readable explanation generated directly from the underlying data (e.g., *"14 failed logins; 2 CRITICAL endpoint alerts; 18 firewall denies on host; Multi-system threat"*).

---

## 5. Security Operations Command Center (Dashboard Navigation)

The redesigned `app.py` features a multi-view console with dedicated analytical perspectives:
1. **🏛️ Command Center Overview**: Top KPI cards, unified cross-system activity timeline, Top 10 At-Risk Identities, Top 10 At-Risk Endpoints, Department risk concentration, signal distribution, and automated analytical insights.
2. **👤 Identity & IAM Investigation**: Authentication failure trends by department, top failure accounts, credential attack signatures, and repeated MFA failure hitlists.
3. **💻 Endpoint Alert Investigation**: EDR severity breakdowns, malware family distributions, target machine criticality, and active threat tables.
4. **🌐 Network & Firewall Investigation**: Geospatial Choropleth threat origin map, protocol deny area trends, and attacked destination port profiles.
5. **🔗 Cross-System Correlation Matrix**: Direct exploration of IAM ↔ Firewall session matches, temporal host proximity correlations, and data model join diagnostics with 1-click CSV export utilities.

---

## 6. How to Run the Application

### 1. Prerequisites
Ensure Python 3.9+ is installed. Dependencies are listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 2. Run the Data Rescue Pipeline
Regenerate high-integrity, fully normalized, timestamp-preserved CSVs:
```bash
python data_rescue.py
```

### 3. Launch the Security Operations Command Center
```bash
streamlit run app.py
```

### 4. Existing AI Agent (Untouched & Standalone)
The bonus Groq-powered AI Agent (`agent.py`) remains completely independent and out of scope:
```bash
streamlit run agent.py
```
*(Requires `GROQ_API_KEY` configured in `.env`)*
