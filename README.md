# TransOrg AgentIQ Datathon — Track 2: Cybersecurity
## Zero-Trust Telemetry & Insider Threat Command Center

---

## 1. Project Title
**Zero-Trust Telemetry & Insider Threat Command Center**  
*TransOrg AgentIQ Datathon — Track 2 Cybersecurity Track*

---

## 2. Track 2 Description
Track 2 focuses on analyzing synthetic enterprise cybersecurity telemetry spanning **Identity & Access Management (IAM)** audit trails, **Endpoint Detection & Response (EDR)** telemetry, **Perimeter Network Firewall** logs, and **Identity/Asset Master** records to detect compromised accounts, malicious execution, lateral movement, and insider threats.

---

## 3. Business Problem
Modern Security Operations Centers (SOCs) are overwhelmed by millions of siloed, noisy logs across disconnected infrastructure. High volumes of authentication failures, malware alerts, and perimeter blocks make it difficult to distinguish legitimate administrative activity from active account compromise and hostile insider threats. The challenge requires ingesting messy, heterogeneous telemetry, repairing corrupted data structures, correlating events across disparate systems without exploding table size, and prioritizing threats through explainable risk scoring.

---

## 4. Solution Overview
We engineered an enterprise-grade "Data to Insights" pipeline featuring:
- **Layer 1 (Data Rescue & Governance)**: Automated pipeline resolving corrupted IDs, stripping domain suffixes, repairing Unix epoch timestamps, normalizing protocols/statuses, and deduplicating records.
- **Layer 2 (Analytics & Data Model)**: Star-schema-inspired relational architecture centering on `DIM_IDENTITY_ASSET` joined to three fact tables (`FACT_IAM`, `FACT_ENDPOINT`, `FACT_FIREWALL`), coupled with a multi-vector cross-system correlation engine.
- **Layer 3 (Executive SOC Dashboard)**: Multi-view interactive command center providing command-level KPIs, activity timelines, threat origin geospatial mapping, entity deep-dives, and 1-click CSV exports.
- **Layer 4 (Bonus Agentic AI)**: Graph-first natural language interface (`agent.py`) powered by Groq LLMs.

---

## 5. Actual Architecture

```
                          DIM_IDENTITY_ASSET (3,000 unique identities)
                          [PK: user_id | Alt Key: hostname_norm]
                                     |
                     +---------------+---------------+
                     |               |               |
                     ↓               ↓               ↓
                 FACT_IAM      FACT_ENDPOINT   FACT_FIREWALL
              (20,000 rows)     (8,000 rows)   (30,000 rows)
              [FK: user_id,    [FK: user_id,   [FK: hostname_norm,
               hostname_norm,   hostname_norm]  session_id_norm]
               session_id_norm]
                     |               |               |
                     +---------------+---------------+
                                     |
                         CROSS-SYSTEM CORRELATION
               (Exact Session Matches & Host Temporal Proximity)
                                     |
                         CENTRALIZED ANALYTICAL LAYER
                    (Timeline aggregation, KPIs, filters)
                                     |
                         BUSINESS LOGIC & RISK SCORING
               (Explainable 0–100 score, Low/Med/High/Crit)
                                     |
                 COMMAND CENTER DASHBOARD (`app.py` UI)
```

---

## 6. Dataset Overview

| Raw Dataset | Format | Raw Rows | Cleaned Rows | Core Telemetry Captured |
| :--- | :--- | :--- | :--- | :--- |
| `track2_identity_asset_master.csv` | CSV | 3,090 | **3,000** | Employee IDs, usernames, departments, hostnames, device IDs, status, hire/termination dates |
| `track2_firewall_logs.csv` | CSV | 30,600 | **30,000** | Network traffic, source/dest IPs, ports, protocols, allow/deny actions, bytes, session IDs, geo countries |
| `track2_iam_audit_trail.json` | JSON | 20,500 | **20,000** | Auth logins/failures, MFA events, account unlocks, session IDs, IP origins, risk scores |
| `track2_endpoint_alerts.xlsx` | Excel | 8,240 | **8,000** | EDR detections, malware types, alert severities, workflow statuses, detection/resolution timestamps |

---

## 7. Data Cleaning Methodology
All transformations are implemented in `transformations.py` and executed via `data_rescue.py`:
1. **User ID Standardization**: Normalized variants (e.g. `EMP 12345`, `emp-12345`, `12345`) to `EMP{digits}` format.
2. **Hostname Standardization**: Stripped domain suffixes (e.g. `.corp.local`), standardized separators (`_` to `-`), and capitalized strings (`LPT_12621` $\rightarrow$ `LPT-12621`).
3. **Department Standardization & Imputation**: Normalized department strings into canonical taxonomy (`IT`, `Finance`, `Sales`, `R&D`, `HR`, `Operations`, `Legal`, `Support`). Backfilled 5,631 missing IAM departments using `DIM_IDENTITY_ASSET`.
4. **Mixed Timestamp Parsing**: Converted standard ISO 8601 strings, mixed regional formats, and raw Unix epoch timestamps (e.g., `1787085290` $\rightarrow$ `2026-08-18 18:48:10+00:00 UTC`) to standard UTC datetime.
5. **Firewall Protocol & Action Normalization**: Mapped IP protocol numbers (`6` $\rightarrow$ `TCP`, `17` $\rightarrow$ `UDP`, `1` $\rightarrow$ `ICMP`) and normalized actions into binary `allow` vs `deny`.
6. **EDR Status & Severity Normalization**: Standardized alert severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and workflow statuses (`NEW`, `OPEN`, `IN_PROGRESS`, `CLOSED`, `FALSE_POSITIVE`).
7. **Telemetry Anomaly Detection**: Flagged 497 alerts exhibiting impossible resolution timestamps (`resolved_timestamp < detected_timestamp`).
8. **Deduplication**: Removed duplicate rows on primary identifiers (`user_id`, `log_id`, `event_id`, `alert_id`).

---

## 8. Validation Methodology
Our validation engine (`validate_cleaning.py`) rigorously validates data integrity, key uniqueness, duplicate removal, and star-schema join match rates before data enters the analytical layer. Every metric is verifiable and reproducible.

---

## 9. Actual Join Relationships

| Source Dataset | Target Dataset | Join Key(s) | Match Rate | Cardinality Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **IAM Fact** | **Identity Master** | `user_id` | **100.0%** (20,000 / 20,000) | Exact 1:1 on PK (0 duplicates, 0 row multiplication) |
| **Endpoint Fact** | **Identity Master** | `user_id` | **100.0%** (8,000 / 8,000) | Exact 1:1 on PK (0 duplicates, 0 row multiplication) |
| **Endpoint Fact** | **Identity Master** | `hostname_norm` | **93.62%** (7,490 / 8,000) | Many:1 on Hostname (backfilled via master) |
| **Firewall Fact** | **Identity Master** | `hostname_norm` | **88.88%** (26,665 / 30,000) | Many:1 on Hostname (high coverage) |

---

## 10. IAM ↔ Firewall Correlation Methodology
Implemented in `correlation.py`:
1. **Exact Session Matching**: Joins IAM audit events with Firewall logs on normalized `session_id_norm`. Yields **320 exact session matches** across 289 unique users.
2. **Host & Temporal Proximity Matching**: Utilizes `pd.merge_asof` to connect IAM authentication actions with firewall connections occurring on the **same host** within a calibrated **$\pm 30$-minute operational window**. Yields **240 proximity matches**.

---

## 11. Analytics & Security Metrics
The centralized analytical layer (`analytical_layer.py` and `business_logic.py`) computes:
- **Core KPIs**: Critical Risk Users, High Risk Users, Total Failed Logins, EDR Alerts, Perimeter Denies, Average Risk Score.
- **Cross-System Activity Timeline**: Daily trend comparing failed authentications, EDR detections, and perimeter blocks.
- **Department Threat Density**: Identifies organizational units with disproportionate threat concentrations.
- **Rule Detections (Rules 1–8)**: Brute force logins ($\ge 5$ fails), MFA fatigue ($\ge 2$ MFA fails), critical malware detections, persistent firewall denial ($\ge 10$ denies), multi-vector user threats, and impossible resolution timestamps.

---

## 12. Risk Scoring Methodology
Located in `risk_scoring.py`, our deterministic 0–100 multi-signal scoring model combines 4 vectors:
- **Identity Component (30%)**: Failed logins, MFA failures, and raw IAM telemetry risk score.
- **Endpoint Component (30%)**: Weighted count of Critical and High EDR alerts.
- **Network Component (20%)**: Host firewall denies and threat flags.
- **Cross-System Correlation (20%)**: Multi-signal concurrency (auth failure + malware alert), terminated user activity, and session-level network links.

**Risk Classification**:
- `CRITICAL`: $\ge 80.0$
- `HIGH`: $60.0 - 79.9$
- `MEDIUM`: $35.0 - 59.9$
- `LOW`: $< 35.0$

Every entity is assigned an explainable justification string (e.g., *"14 failed logins; 2 CRITICAL endpoint alerts; 18 firewall denies on host; Multi-system threat"*).

---

## 13. Dashboard Sections (`app.py`)
1. **🏛️ Command Center Overview**: High-level KPI cards, unified activity trend, Top 10 At-Risk Identities & Endpoints, Department risk bar chart, Signal breakdown pie chart, and automated insight cards.
2. **👤 Identity & IAM Investigation**: Failure trend by department, top failure accounts, credential failure reasons bar chart, and Rule 2 MFA failure table.
3. **💻 Endpoint Alert Investigation**: EDR alert types by severity, workflow status breakdown, impossible resolution timestamps anomaly tab (Rule 8), and critical malware detections table.
4. **🌐 Network & Firewall Investigation**: Geospatial Choropleth threat origin map (perimeter denies by country), normalized protocol deny area trend (TCP/UDP/ICMP), top blocked destination ports, and high-threat host profiles.
5. **🔗 Cross-System Correlation Matrix**: Direct exploration of IAM ↔ Firewall session matches (with CSV download), host temporal proximity matches, star-schema join quality diagnostics, and interactive entity drilldown.

---

## 14. Filters & Interactivity
- **Department Scope Multi-Select**: Dynamically filters all KPIs, timelines, tables, and charts across all 5 views.
- **Risk Level Multi-Select**: Filters entities by `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- **Interactive Drill-Down Selectors**: Select target suspicious user to inspect full telemetry trail.
- **1-Click CSV Exports**: Download correlated session events and proximity logs for external SIEM ingestion.

---

## 15. Cross-System Investigation Workflow
Analysts can select any high-risk user in View 5 to trace their complete lifecycle:
$$\text{User Context} \longrightarrow \text{IAM Events} \longrightarrow \text{Assigned Host} \longrightarrow \text{EDR Alerts} \longrightarrow \text{Perimeter Firewall Blocks}$$

---

## 16. Data Dictionary Location
The comprehensive Data Dictionary defining all tables, fields, types, and derivation rules is located at:  
[`data_dictionary.md`](file:///c:/Users/kenpa/OneDrive/Desktop/Datathon/data_dictionary.md)

---

## 17. Cleaning Proof Location
The reproducible Data Rescue & Cleaning Proof Report is located at:  
[`cleaning_report.md`](file:///c:/Users/kenpa/OneDrive/Desktop/Datathon/cleaning_report.md)

---

## 18. Project File Structure

```
Datathon/
├── README.md                           # Master project documentation (all 23 rubric sections)
├── data_dictionary.md                  # Complete Data Dictionary (Gate 1)
├── cleaning_report.md                  # Data Rescue & Cleaning Proof Report (Gate 2)
├── project_report.md                   # Executive datathon summary report
├── requirements.txt                    # Project python dependencies
│
├── transformations.py                  # Core cleaning, normalization, and parsing functions
├── data_rescue.py                      # Automated data cleaning pipeline (Gate 2)
├── validate_cleaning.py                # Standalone validation and join diagnostics script
├── data_model.py                       # Star-schema model builder (DIM & FACT tables)
├── correlation.py                      # IAM ↔ Firewall session & proximity correlation engine
├── risk_scoring.py                     # Deterministic multi-vector 0-100 risk scoring engine
├── analytical_layer.py                 # Centralized metric aggregations and timeline generator
├── business_logic.py                   # Explicit cybersecurity detection rules (Rules 1-8)
│
├── app.py                              # SOC Command Center Streamlit Dashboard (Layer 3)
├── agent.py                            # Standalone Groq-powered AI Agent (Layer 4 - Untouched)
│
├── eda_initial.py                      # Initial exploratory data analysis script
├── eda_detailed.py                     # Detailed exploratory analysis script
│
├── track2_identity_asset_master.csv    # Raw Identity/Asset master data
├── track2_firewall_logs.csv            # Raw Firewall logs
├── track2_iam_audit_trail.json         # Raw IAM audit trail
├── track2_endpoint_alerts.xlsx         # Raw Endpoint alerts
├── track2_dataset_notes.txt            # Official Track 2 prompt guidelines
│
├── cleaned_identity_asset_master.csv   # Cleaned DIM_IDENTITY_ASSET table
├── cleaned_firewall_logs.csv           # Cleaned FACT_FIREWALL table
├── cleaned_iam_audit_trail.csv         # Cleaned FACT_IAM table
└── cleaned_endpoint_alerts.csv         # Cleaned FACT_ENDPOINT table
```

---

## 19. Installation
Ensure Python 3.9+ is installed. Install all dependencies via pip:
```bash
pip install -r requirements.txt
```

---

## 20. Exact Run Instructions

### To run the SOC Command Center Dashboard:
```bash
streamlit run app.py
```

### To run the Standalone Validation Script:
```bash
python validate_cleaning.py
```

---

## 21. Reproducibility Sequence

```bash
# Step 1: Install dependencies
pip install -r requirements.txt

# Step 2: Run data rescue pipeline
python data_rescue.py

# Step 3: Verify data integrity and join diagnostics
python validate_cleaning.py

# Step 4: Launch the SOC Command Center Dashboard
streamlit run app.py
```

---

## 22. Limitations
1. **Synthetic Telemetry**: The data is synthetically generated for datathon purposes; certain network flows lack associated hostnames in the perimeter log.
2. **Temporal Gaps**: Exact session matches between IAM and Firewall show temporal dispersion reflective of synthetic session ID re-use across distinct timeframes.
3. **Firewall User Identity**: Firewall logs record device hostnames rather than authenticated usernames; identity attribution relies on star-schema asset mapping.

---

## 23. Bonus AI Agent (`agent.py`)
The standalone Graph-First AI Agent (`agent.py`) provides natural-language-to-chart intelligence powered by Groq:
- **Intents Handled**: `failed_logins_trend`, `alerts_by_severity`, `top_failed_users`, `firewall_deny_trend`, `help`.
- **Run Command**:
  ```bash
  streamlit run agent.py
  ```
  *(Requires `GROQ_API_KEY` in `.env`)*
