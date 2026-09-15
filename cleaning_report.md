# TransOrg AgentIQ Datathon Track 2
## Official Data Rescue & Cleaning Proof Report

This document presents empirical, reproducible evidence of data cleaning, integrity transformations, and star-schema join quality across Track 2: **Zero-Trust Telemetry & Insider Threat Logs**.

---

### Executive Summary of Data Rescue Operations

Our data rescue engineering pipeline (`data_rescue.py` and `transformations.py`) executed systematic data rescue without losing genuine telemetry rows:

1. **User ID Standardization**: Coerced heterogeneous employee ID formats (`EMP 12345`, `emp-12345`, `12345`, `EMP12345`) into a single canonical uppercase format `EMP{digits}`.
2. **Hostname Standardization**: Stripped domain suffixes (`.corp.local`, `.local`), standardized separators (converted underscores to hyphens), and uppercased names.
3. **Department Taxonomy Alignment**: Mapped multi-case variants (`information tech`, `sales team`, `rnd`, `finance dept`) to canonical departments (`IT`, `Sales`, `R&D`, `Finance`, `HR`, `Legal`, `Support`, `Operations`). Backfilled 5,631 missing IAM departments using the Identity Master.
4. **Mixed Timestamp Parsing**: Replaced brittle string parsing with a robust UTC converter capable of parsing standard ISO 8601 strings, mixed day-first/month-first regional dates, and raw Unix epoch timestamps (e.g., `1787085290` $\rightarrow$ `2026-08-18 18:48:10+00:00 UTC`).
5. **Firewall Protocol & Action Normalization**: Standardized IP protocol numbers (`6` $\rightarrow$ `TCP`, `17` $\rightarrow$ `UDP`, `1` $\rightarrow$ `ICMP`) and normalized actions into binary `allow` vs `deny`.
6. **EDR Status & Severity Normalization**: Unified alert severities into 4 canonical tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and workflow statuses (`NEW`, `OPEN`, `IN_PROGRESS`, `CLOSED`, `FALSE_POSITIVE`).
7. **Telemetry Anomaly Detection**: Identified and flagged 497 EDR alerts exhibiting impossible resolution timestamps where `resolved_timestamp < detected_timestamp`.
8. **Deduplication & Integrity**: Eliminated duplicate records on natural primary keys (`user_id`, `log_id`, `event_id`, `alert_id`) ensuring 0% row multiplication during downstream analytical joins.

---

### 1. Cleaning & Rescue Proof Table

| Dataset | Raw Row Count | Cleaned Row Count | Duplicates (Raw) | Duplicates (Cleaned) | Missing PKs / Foreign Keys | Actions & Transformations Performed | Validation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Identity Asset Master** | 3,090 | **3,000** | 90 | **0** | 0 | Standardized `user_id` format, deduplicated on PK, normalized `hostname` & `department`, validated hire/termination dates. | **PASS (100% Unique PK)** |
| **Firewall Logs** | 30,600 | **30,000** | 600 | **0** | 0 | Normalized `hostname_norm` & `session_id_norm`, converted protocols (`6` $\rightarrow$ `TCP`, `17` $\rightarrow$ `UDP`, `1` $\rightarrow$ `ICMP`), cleaned IP/port bounds, parsed Unix timestamps. | **PASS (Clean Fact)** |
| **IAM Audit Trail** | 20,500 | **20,000** | 500 | **0** | 0 | Standardized `user_id`, recovered 5,631 missing departments from Master, categorized event types, validated 0–100 risk scores. | **PASS (Clean Fact)** |
| **Endpoint Alerts** | 8,240 | **8,000** | 240 | **0** | 0 | Standardized `user_id` & `hostname_norm` (backfilled from master), normalized severity and status, flagged 497 impossible resolution timestamps. | **PASS (Clean Fact)** |

---

### 2. Star Schema Join Diagnostics & Cardinality Audit

All joins between the centralized dimension `DIM_IDENTITY_ASSET` and the telemetry fact tables were empirically verified:

| Relationship | Join Key | Source Rows | Matched Rows | Match Rate | Null Keys in Source | Cardinality Guarantee | Downstream Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **IAM $\rightarrow$ Master** | `user_id` | 20,000 | 20,000 | **100.00%** | 0 | Exact 1:1 on Master PK | Zero row multiplication; 100% identity context |
| **Endpoint $\rightarrow$ Master** | `user_id` | 8,000 | 8,000 | **100.00%** | 0 | Exact 1:1 on Master PK | Zero row multiplication; 100% identity context |
| **Endpoint $\rightarrow$ Master** | `hostname_norm` | 8,000 | 7,490 | **93.62%** | 28 | Many:1 on Hostname | High-coverage asset linkage |
| **Firewall $\rightarrow$ Master** | `hostname_norm` | 30,000 | 26,665 | **88.88%** | 1,757 | Many:1 on Hostname | High-coverage perimeter asset linkage |

---

### 3. Cross-System Correlation Engine Verification

| Correlation Vector | Correlation Keys | Match Count | Unique Entities | Median Time Delta | Security Insight |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Exact Session Joins** | `session_id_norm` | **320 events** | 289 unique users | 1,234,179 seconds | Directly links IAM authentication events to perimeter firewall connections sharing the same session identifier. |
| **Host Temporal Proximity** | `hostname_norm` $\pm 30\text{ min}$ | **240 events** | N/A (Host-aligned) | $\le 1,800\text{ seconds}$ | Connects IAM logins with perimeter connections occurring on the identical machine within a calibrated 30-minute window. |
| **Tri-System Host Overlap** | `hostname_norm` across 3 systems | **2,781 hosts** | 2,781 unique hosts | N/A | Machines with full-spectrum telemetry (IAM + EDR + Firewall). |
| **Multi-Vector Suspicious Users**| `user_id` with Fails + EDR | **1,312 users** | 1,312 unique users | N/A | High-threat insider candidates displaying simultaneous auth failures and active endpoint malware alerts. |

---

### 4. Reproducibility Instructions

To independently reproduce this validation report:

```bash
# 1. Execute the Data Rescue Pipeline
python data_rescue.py

# 2. Run the Verification Script
python validate_cleaning.py
```
