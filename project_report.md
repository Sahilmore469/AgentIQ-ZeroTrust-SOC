# TransOrg AgentIQ Datathon: Track 2 Project Report
**Track 2: Cybersecurity - Zero-Trust Telemetry & Insider Threat Logs**

---

## 1. Executive Summary

**The Business Problem:**
Modern cybersecurity command centers face the daunting challenge of detecting compromised identities, lateral movement, and insider threats amidst massive, fragmented, and noisy telemetry streams across Identity & Access Management (IAM), Endpoint Detection & Response (EDR), and Network Firewalls.

**Our Solution:**
We architected and implemented an enterprise-grade "Data to Insights" pipeline featuring:
1. **Automated Data Rescue & Engineering**: Rescued corrupted telemetry, standardized foreign keys, recovered Unix epoch timestamps, normalized protocols/statuses, and eliminated duplicates without losing legitimate events.
2. **Star-Schema Analytical Data Model**: Structured data around `DIM_IDENTITY_ASSET` connected to `FACT_IAM`, `FACT_ENDPOINT`, and `FACT_FIREWALL`.
3. **Cross-System Correlation Engine**: Linked IAM authentication events and perimeter firewall traffic using shared `session_id_norm` (320 exact matches) and host temporal proximity ($\pm 30$ min, 240 matches).
4. **Explainable Multi-Signal Risk Scoring**: Synthesized identity, endpoint, network, and cross-system threat vectors into a deterministic 0–100 score with human-readable justifications.
5. **Interactive SOC Command Center**: Built a 5-view Streamlit dashboard with global cascading filters, interactive entity drill-downs, and CSV exports.
6. **Bonus Agentic AI Interface**: Retained standalone natural-language query capabilities via `agent.py`.

---

## 2. Gate 1: Compliance, Sanity & Data Governance
- **Data Dictionary**: Published [`data_dictionary.md`](file:///c:/Users/kenpa/OneDrive/Desktop/Datathon/data_dictionary.md) detailing all schemas, field definitions, data types, valid domains, key relationships, and derivation rules.
- **Reproducible Pipeline**: All cleaning and validation steps are completely reproducible via `python data_rescue.py` and `python validate_cleaning.py`.
- **Accurate Documentation**: Comprehensive `README.md` reflecting the exact code implementation, actual join statistics, and exact run commands.

---

## 3. Gate 2: Data Rescue & Engineering
Our pipeline (`data_rescue.py` and `transformations.py`) executed systematic data rescue across all 4 datasets:
- **ID Standardization**: Standardized messy user IDs (`EMP 12345`, `emp-12345`, `12345`) to `EMP{digits}` format, achieving 100.0% join rates to Identity Master.
- **Hostname Normalization**: Stripped `.corp.local` domain suffixes, replaced underscores with hyphens, and uppercased hostnames, boosting EDR match rates to 93.62% and Firewall match rates to 88.88%.
- **Timestamp Recovery**: Resolved mixed regional strings and converted raw Unix timestamps (e.g. `1787085290` $\rightarrow$ August 18, 2026 UTC) to standard UTC datetime.
- **Protocol & Status Normalization**: Standardized IP protocol numbers (`6` $\rightarrow$ `TCP`, `17` $\rightarrow$ `UDP`, `1` $\rightarrow$ `ICMP`) and EDR statuses (`NEW`, `OPEN`, `IN_PROGRESS`, `CLOSED`, `FALSE_POSITIVE`).
- **Telemetry Integrity Anomaly**: Flagged 497 alerts with impossible resolution timestamps (`resolved_timestamp < detected_timestamp`).
- **Code Documentation**: Meticulously documented every transformation decision with explicit `# DECISION:` inline comments.

*Validation Summary:*
- Master: 3,090 raw $\rightarrow$ 3,000 clean rows (0 duplicates, 100% unique PK).
- Firewall: 30,600 raw $\rightarrow$ 30,000 clean rows (600 duplicates removed).
- IAM: 20,500 raw $\rightarrow$ 20,000 clean rows (500 duplicates removed, 5,631 missing departments backfilled).
- Endpoint: 8,240 raw $\rightarrow$ 8,000 clean rows (240 duplicates removed).

---

## 4. Gate 3: Executive Dashboarding & Business Value
Built `app.py` using Streamlit and Plotly, delivering 5 comprehensive operational views:
1. **Command Center Overview**: Top security KPI cards, unified cross-system activity timeline, Top 10 At-Risk Identities, Top 10 At-Risk Endpoints, Department risk concentration, and automated analytical insights.
2. **Identity & IAM Investigation**: Authentication failure trends by department, top failure accounts, credential attack signatures, and repeated MFA failure hitlists (Rule 2).
3. **Endpoint Alert Investigation**: EDR severity breakdowns, workflow status distributions, impossible resolution timestamps anomaly table, and critical threat tables.
4. **Network & Firewall Investigation**: Geospatial Choropleth threat origin map, protocol deny area trends, top blocked destination ports, and high-threat host profiles.
5. **Cross-System Correlation Matrix & Entity Deep-Dive**: Direct exploration of IAM ↔ Firewall session matches, temporal proximity correlations, data model diagnostics, and interactive user-to-threat trace drilldown.

---

## 5. Gate 4: Excellence & Bonus AI Agent
- **Modular Codebase**: Clean separation of concerns across `transformations.py`, `data_rescue.py`, `data_model.py`, `correlation.py`, `risk_scoring.py`, `analytical_layer.py`, `business_logic.py`, and `app.py`.
- **Bonus AI Agent (`agent.py`)**: Fully preserved and operational for natural language queries (powered by Groq).

---

## 6. Conclusion
By applying disciplined data engineering, robust star-schema modeling, and explainable multi-signal risk analytics, we delivered an enterprise-grade cybersecurity command center that bridges raw logs into actionable threat intelligence.
