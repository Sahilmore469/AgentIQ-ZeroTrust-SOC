# Track 2: Cybersecurity - Data Dictionary
## Zero-Trust Telemetry & Insider Threat Logs

This Data Dictionary defines all tables, entities, attributes, data types, valid value domains, join key roles, and derivation logic across the Star-Schema Analytical Architecture.

---

### Conceptual Architecture Overview

```
                      DIM_IDENTITY_ASSET (Primary Dimension)
                      [PK: user_id | Alt Key: hostname_norm]
                                 |
                 +---------------+---------------+
                 |               |               |
                 ↓               ↓               ↓
             FACT_IAM      FACT_ENDPOINT   FACT_FIREWALL
            [FK: user_id,  [FK: user_id,   [FK: hostname_norm,
             hostname_norm, hostname_norm]  session_id_norm]
             session_id_norm]
                 |               |               |
                 +---------------+---------------+
                                 |
                     CROSS-SYSTEM CORRELATION
           [Session matching & Host Temporal Proximity]
```

---

## 1. `DIM_IDENTITY_ASSET` (Identity & Asset Master Dimension)
- **Source File**: `track2_identity_asset_master.csv` / `cleaned_identity_asset_master.csv`
- **Granularity**: 1 row per unique enterprise identity / employee.
- **Record Count**: 3,000 clean rows (100% unique primary key).

| Column Name | Data Type | Role / Key | Derivation Status | Description & Meaning | Example / Valid Domain |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user_id` | `VARCHAR` | **Primary Key (PK)** | Cleaned / Standardized | Canonical Employee ID format (`EMP` + digits). Primary join key to IAM and EDR facts. | `EMP10001`, `EMP12999` |
| `username` | `VARCHAR` | Attribute | Original | Corporate active directory username. | `jdoe`, `asmith` |
| `full_name` | `VARCHAR` | Attribute | Original | Full legal name of the employee. | `Jane Doe`, `Alice Smith` |
| `department` | `VARCHAR` | Attribute | Cleaned / Standardized | Normalized department name according to canonical enterprise taxonomy. | `IT`, `Finance`, `Sales`, `R&D`, `HR`, `Operations`, `Legal`, `Support` |
| `role` | `VARCHAR` | Attribute | Original | Assigned organizational job role / title. | `Security Analyst`, `Software Engineer`, `Sales Manager` |
| `location` | `VARCHAR` | Attribute | Original | Primary office or geographic work location. | `New York`, `London`, `Remote` |
| `hostname` | `VARCHAR` | Attribute | Original | Raw asset hostname assigned to employee. | `LPT-10492`, `VDR-11307.corp.local` |
| `hostname_norm` | `VARCHAR` | **Alternate Key (AK)** | Derived / Cleaned | Normalized uppercase hostname with domain suffixes stripped and separators unified. | `LPT-10492`, `VDR-11307` |
| `device_id` | `VARCHAR` | Attribute | Original | Unique hardware device identifier. | `DEV-98421` |
| `status` | `VARCHAR` | Attribute | Original | Raw employment status. | `Active`, `Terminated`, `Leave` |
| `status_norm` | `VARCHAR` | Attribute | Derived / Cleaned | Canonical employment status. | `Active`, `Terminated`, `On Leave`, `Unknown` |
| `hire_date` | `DATETIME (UTC)` | Attribute | Parsed (UTC) | Employment start timestamp in standard UTC. | `2021-03-15 00:00:00+00:00` |
| `termination_date` | `DATETIME (UTC)` | Attribute | Parsed (UTC) | Employment end timestamp (null for active employees). | `2026-06-30 00:00:00+00:00` |
| `manager_username` | `VARCHAR` | Attribute | Original | Corporate username of the employee's direct supervisor. | `mbrown`, `cjones` |

---

## 2. `FACT_IAM` (Identity & Access Management Fact Table)
- **Source File**: `track2_iam_audit_trail.json` / `cleaned_iam_audit_trail.csv`
- **Granularity**: 1 row per identity authentication / access event.
- **Record Count**: 20,000 clean rows.

| Column Name | Data Type | Role / Key | Derivation Status | Description & Meaning | Example / Valid Domain |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `VARCHAR` | **Event PK** | Original | Unique IAM event tracking identifier. | `EVT100001` |
| `timestamp` | `DATETIME (UTC)` | Temporal Metric | Parsed (UTC) | UTC timestamp of the authentication/access action (recovering Unix epochs & mixed strings). | `2026-08-18 14:22:10+00:00` |
| `user_id` | `VARCHAR` | **Foreign Key (FK)** | Cleaned / Standardized | Standardized Employee ID joining to `DIM_IDENTITY_ASSET.user_id` (100.0% match rate). | `EMP10492` |
| `username` | `VARCHAR` | Attribute | Original | Username claimed during login attempt. | `jdoe` |
| `department` | `VARCHAR` | Dimension Attribute | Standardized / Imputed | Normalized department taxonomy. Missing values backfilled from Master via `user_id`. | `IT`, `Finance`, `Sales`, `R&D` |
| `event_type` | `VARCHAR` | Attribute | Original | Raw event description from IAM provider. | `SSO_SUCCESS`, `FAILED_LOGIN`, `MFA_FAILED` |
| `event_category` | `VARCHAR` | Analytical Dimension | Derived / Categorized | Canonical classification into `login_success`, `login_failed`, `mfa_failure`, `other`. | `login_success`, `login_failed`, `mfa_failure`, `other` |
| `auth_method` | `VARCHAR` | Attribute | Original | Authentication protocol used. | `Password`, `SSO`, `Kerberos`, `OAuth` |
| `source_ip` | `VARCHAR` | Network Metric | Cleaned / Validated | Validated client IPv4 address initiating authentication. Invalid octets set to NaN. | `192.168.1.50`, `10.0.4.12` |
| `hostname` | `VARCHAR` | Attribute | Original | Raw hostname recorded during authentication. | `WS-1002` |
| `hostname_norm` | `VARCHAR` | **Foreign Key (FK)** | Cleaned / Imputed | Normalized hostname. Missing values backfilled from Master when user is known. | `WS-1002`, `LPT-12621` |
| `session_id` | `VARCHAR` | Attribute | Original | Raw authentication session token / identifier. | `sid-191825` |
| `session_id_norm` | `VARCHAR` | **Correlation Key (CK)**| Cleaned / Standardized | Standardized session ID used for exact IAM ↔ Firewall correlation. | `SID191825` |
| `mfa_passed` | `BOOLEAN` | Security Flag | Cleaned | Indicates whether multi-factor authentication was completed successfully. | `True`, `False` |
| `failure_reason` | `VARCHAR` | Threat Indicator | Original | Explanatory reason when authentication fails. | `Invalid Password`, `Account Locked`, `Expired Token` |
| `risk_score` | `FLOAT (0-100)` | Telemetry Metric | Cleaned / Bounded | Provider-assigned IAM anomaly score coerced to float in range [0.0, 100.0]. | `85.0`, `12.5` |
| `geo_location` | `VARCHAR` | Spatial Attribute | Original | Country or city from which connection originated. | `US`, `DE`, `IN`, `CN` |

---

## 3. `FACT_ENDPOINT` (Endpoint Detection & Response Alerts Fact Table)
- **Source File**: `track2_endpoint_alerts.xlsx` / `cleaned_endpoint_alerts.csv`
- **Granularity**: 1 row per host EDR detection alert.
- **Record Count**: 8,000 clean rows.

| Column Name | Data Type | Role / Key | Derivation Status | Description & Meaning | Example / Valid Domain |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `alert_id` | `VARCHAR` | **Alert PK** | Original | Unique EDR alert detection identifier. | `EPA00005098` |
| `detected_timestamp` | `DATETIME (UTC)` | Temporal Metric | Parsed (UTC) | UTC timestamp when suspicious host behavior was first detected. | `2026-09-04 19:36:51+00:00` |
| `resolved_timestamp` | `DATETIME (UTC)` | Temporal Metric | Parsed (UTC) | UTC timestamp when alert was closed or resolved. | `2026-09-04 20:10:00+00:00` |
| `impossible_resolution_flag`| `BOOLEAN` | Integrity Flag | Derived / Anomaly | `True` if `resolved_timestamp < detected_timestamp` (impossible resolution anomaly). | `True`, `False` |
| `hostname` | `VARCHAR` | Attribute | Original | Raw host machine where alert triggered. | `LPT-12440` |
| `hostname_norm` | `VARCHAR` | **Foreign Key (FK)** | Cleaned / Imputed | Normalized hostname (93.62% match to Master). Missing hostnames backfilled via `user_id`. | `LPT-12440` |
| `user_id` | `VARCHAR` | **Foreign Key (FK)** | Cleaned / Standardized | Standardized Employee ID joining to `DIM_IDENTITY_ASSET.user_id` (100.0% match rate). | `EMP12440` |
| `endpoint_product` | `VARCHAR` | Attribute | Original | EDR agent software platform. | `CrowdStrike`, `Defender`, `SentinelOne` |
| `alert_name` | `VARCHAR` | Threat Indicator | Original | Threat classification or rule name. | `Ransomware Behavior`, `Mimikatz Execution`, `PowerShell Anomaly` |
| `severity` | `VARCHAR` | Risk Metric | Cleaned / Categorized | Standardized 4-tier alert severity. | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` |
| `status` | `VARCHAR` | Attribute | Original | Raw analyst ticket workflow status. | `New`, `In Progress`, `Resolved`, `Closed` |
| `status_norm` | `VARCHAR` | Attribute | Derived / Categorized | Canonical workflow status. | `NEW`, `OPEN`, `IN_PROGRESS`, `CLOSED`, `FALSE_POSITIVE` |
| `file_path` | `VARCHAR` | Forensic Artifact | Original | Local filesystem path of offending binary. | `C:\Users\admin\AppData\malware.exe` |
| `process_name` | `VARCHAR` | Forensic Artifact | Original | Name of executing process. | `powershell.exe`, `cmd.exe`, `svchost.exe` |
| `sha256` | `VARCHAR` | Threat Hash | Original | Cryptographic SHA-256 hash of malicious artifact. | `e3b0c44298fc1c149afbf4c8996fb924...` |
| `device_criticality` | `VARCHAR` | Asset Metric | Original | Asset business criticality tier. | `Tier 1 (Domain Controller)`, `Tier 2`, `Tier 3` |

---

## 4. `FACT_FIREWALL` (Network Perimeter Telemetry Fact Table)
- **Source File**: `track2_firewall_logs.csv` / `cleaned_firewall_logs.csv`
- **Granularity**: 1 row per network flow / packet inspection log.
- **Record Count**: 30,000 clean rows.

| Column Name | Data Type | Role / Key | Derivation Status | Description & Meaning | Example / Valid Domain |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `log_id` | `VARCHAR` | **Log PK** | Original | Unique perimeter firewall log record identifier. | `FWL100001` |
| `timestamp` | `DATETIME (UTC)` | Temporal Metric | Parsed (UTC) | UTC timestamp of perimeter packet inspection (recovering Unix epochs & mixed strings). | `2026-08-18 14:25:00+00:00` |
| `hostname` | `VARCHAR` | Attribute | Original | Raw internal hostname associated with network connection. | `VDR-11307.corp.local` |
| `hostname_norm` | `VARCHAR` | **Foreign Key (FK)** | Cleaned / Standardized | Normalized hostname joining to `DIM_IDENTITY_ASSET.hostname_norm` (88.88% match rate). | `VDR-11307`, `LPT-10021` |
| `src_ip` | `VARCHAR` | Network Metric | Cleaned / Validated | Validated source IPv4 address. Invalid octets set to NaN. | `10.0.1.25`, `192.168.0.10` |
| `dst_ip` | `VARCHAR` | Network Metric | Cleaned / Validated | Validated destination IPv4 address. | `198.51.100.22`, `203.0.113.1` |
| `src_port` | `INTEGER` | Network Metric | Cleaned / Bounded | Validated source TCP/UDP port (1–65535). | `49152`, `54321` |
| `dst_port` | `INTEGER` | Network Metric | Cleaned / Bounded | Validated destination port (e.g., 80, 443, 22, 3389, 445). | `443`, `22`, `3389`, `445` |
| `protocol` | `VARCHAR` | Network Dimension | Cleaned / Standardized | Standardized protocol name (6 -> TCP, 17 -> UDP, 1 -> ICMP). | `TCP`, `UDP`, `ICMP` |
| `action` | `VARCHAR` | Security Action | Cleaned / Standardized | Canonical binary firewall perimeter enforcement action. | `allow`, `deny` |
| `bytes_sent` | `FLOAT` | Traffic Volume | Cleaned / Coerced | Number of bytes sent through connection. Extracted from numeric/string formats. | `4096.0`, `1048576.0` |
| `bytes_received` | `FLOAT` | Traffic Volume | Cleaned / Coerced | Number of bytes received through connection. | `8192.0`, `5242880.0` |
| `session_id` | `VARCHAR` | Attribute | Original | Raw session token from network stream. | `sid-191825` |
| `session_id_norm` | `VARCHAR` | **Correlation Key (CK)**| Cleaned / Standardized | Standardized session ID used for exact IAM ↔ Firewall correlation. | `SID191825` |
| `threat_flag` | `BOOLEAN` | Threat Indicator | Cleaned / Standardized | Standardized boolean indicator: `True` if firewall IDS/IPS flagged traffic as malicious. | `True`, `False` |
| `rule_name` | `VARCHAR` | Security Policy | Original | Name of firewall security policy rule triggered. | `Block_Malicious_IPs`, `Allow_HTTPS_Outbound` |
| `geo_country` | `VARCHAR` | Spatial Metric | Original | Geographic destination/origin country name for choropleth mapping. | `United States`, `Germany`, `China`, `Russia` |

---

## 5. Derived Risk Scoring & Correlation Tables

### A. User Risk Profile (`calculate_user_risk_profile`)
| Field | Type | Description |
| :--- | :--- | :--- |
| `user_id` | `VARCHAR` | Canonical Employee ID. |
| `full_name` | `VARCHAR` | Employee Name from Identity Master. |
| `department` | `VARCHAR` | Canonical Department. |
| `status_norm` | `VARCHAR` | Employee Status (`Active`, `Terminated`, `On Leave`). |
| `hostname_norm` | `VARCHAR` | Primary Hostname assigned to employee. |
| `failed_logins` | `INT` | Total failed authentications in `FACT_IAM`. |
| `mfa_failures` | `INT` | Total MFA rejections in `FACT_IAM`. |
| `avg_iam_risk` | `FLOAT` | Average raw telemetry risk score in `FACT_IAM`. |
| `critical_alerts` | `INT` | Total CRITICAL severity alerts in `FACT_ENDPOINT`. |
| `high_alerts` | `INT` | Total HIGH severity alerts in `FACT_ENDPOINT`. |
| `host_fw_denies` | `INT` | Total firewall `deny` actions on assigned host in `FACT_FIREWALL`. |
| `risk_score` | `FLOAT (0-100)` | Multi-signal deterministic risk score: Identity (30%) + EDR (30%) + Network (20%) + Cross-Correlation (20%). |
| `risk_level` | `VARCHAR` | `CRITICAL` (>=80), `HIGH` (60-79.9), `MEDIUM` (35-59.9), `LOW` (<35). |
| `main_reason` | `VARCHAR` | Human-readable explanation of risk contributors based strictly on observed data. |

### B. Cross-System Correlation (`correlate_iam_firewall_sessions` & `correlate_iam_firewall_proximity`)
| Field | Type | Description |
| :--- | :--- | :--- |
| `session_id_norm` | `VARCHAR` | Standardized session ID common to IAM and Firewall. |
| `user_id` | `VARCHAR` | Authenticated user from IAM. |
| `timestamp_iam` | `DATETIME (UTC)` | Exact authentication timestamp. |
| `timestamp_fw` | `DATETIME (UTC)` | Firewall connection timestamp. |
| `time_diff_sec` | `FLOAT` | Temporal difference ($t_{\text{FW}} - t_{\text{IAM}}$) in seconds. |
| `same_host` | `BOOLEAN` | `True` if `hostname_norm_iam == hostname_norm_fw`. |
| `action` | `VARCHAR` | Firewall action (`allow` or `deny`). |
| `dst_ip` | `VARCHAR` | Remote destination IP. |
| `correlation_type`| `VARCHAR` | `SESSION_MATCH` or `TEMPORAL_PROXIMITY_30M`. |
