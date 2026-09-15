# TransOrg AgentIQ Datathon: Track 2 Project Report
**Track 2: Cybersecurity - Zero-Trust Telemetry & Insider Threat Logs**

---

## 1. Executive Summary
**The Business Problem:**
A cyber-command center faced the challenge of detecting compromised accounts and insider threats. However, the underlying data—comprising millions of network logs and IAM (Identity and Access Management) audit trails—was incredibly noisy, unstructured, and fragmented across different systems.

**Our Solution:**
We developed a complete, end-to-end "Data to Insights" pipeline. We built an automated Python data rescue script to clean and unify the messy logs. We then built a live, interactive Streamlit Executive Dashboard to visualize threat metrics. Finally, we engineered a Graph-First AI Agent (powered by Groq and Llama 3) that allows security analysts to query the data using natural language.

---

## 2. Gate 2: Data Rescue & Engineering
The provided synthetic datasets (`firewall_logs`, `iam_audit_trail`, `endpoint_alerts`, `identity_asset_master`) were highly unstructured. We built `data_rescue.py` using `pandas` to execute the following cleaning operations:

* **ID Standardization:** Employee IDs were in multiple formats (e.g., `EMP 12345`, `emp-12345`). We used Regular Expressions (Regex) to strip non-numeric characters and uniformly prepend `EMP`, ensuring a perfect join key across tables.
* **Categorical Normalization:** Department names (`information tech` -> `IT`) and Alert Severities (`Severe`, `P1`, `CRIT` -> `CRITICAL`) were mapped to standardized dictionaries.
* **Timestamp Parsing:** We encountered a mix of US, EU, and ISO datetime strings. We utilized robust Pandas datetime parsing (`format='mixed'`) to cast all temporal data into standard UTC structures.
* **Firewall Logic:** Mapped dozens of firewall action variants (e.g., `PASS`, `PERMIT`, `allow`) into binary `allow` or `deny` classifications, and coerced messy string byte counts into clean floats.
* **Data Integrity:** Handled missing values via intelligent imputation, ran regex validation on IP addresses, and removed duplicate rows across all 4 datasets.
* **Code Documentation (10 Bonus Pts):** Every major data cleaning operation in the script is accompanied by an explicit `# DECISION:` inline comment, meticulously documenting the rationale behind our pipeline architecture.

*Proof of Cleaning:* Our pipeline reduced noise and dropped duplicates seamlessly (e.g., Firewall logs were reduced from 30,600 raw rows to exactly 30,000 clean, usable rows).

---

## 3. Gate 3: Executive Dashboarding & Analytics
With clean data, we built `app.py`, a robust Python-based web dashboard using **Streamlit** and **Plotly**.

**Key Features & Advanced Insights:**
* **Global Interactivity:** A sidebar allows the CISO or security analyst to filter the entire dashboard by specific company departments.
* **Geospatial Threat Mapping:** We engineered an interactive Plotly `choropleth` map that plots firewall `deny` actions by `geo_country`, providing a real-time visualization of where global network attacks are originating.
* **Core KPIs & Gauges:** At a glance, the dashboard calculates Total Failed Logins, Critical Endpoint Alerts, and Total Firewall Blocks. The Average IAM Risk Score is visualized using an intuitive, color-coded Plotly Gauge Chart.
* **Threat Storytelling:** 
    * A Line Chart tracks the trend of failed login attempts over time.
    * An Area Chart maps Firewall Deny actions by network protocol.
    * A Bar Chart exposes the Top 10 users with the most failed authentications.
* **Actionable Suspicious User Matrix:** We cross-referenced the `IAM` and `Endpoint Alerts` tables to generate a dynamic table highlighting "Suspicious Users"—employees with an unusually high number of failed logins *and* active endpoint alerts. We included a **1-click CSV Export** button, allowing SOC teams to instantly download the hitlist for remediation.

---

## 4. Gate 4: The Bonus AI Agent (AgentIQ)
To fulfill the ultimate Datathon challenge, we built `agent.py`, a Graph-First AI assistant.

**Architecture & Code Elegance:**
* **Dynamic LLM Engine:** We utilized **Groq's API** for ultra-fast natural language inference. We architected the application to pull the `GROQ_MODEL` dynamically from a `.env` file, future-proofing the agent against model deprecations without requiring source code changes.
* **Intent Routing & UX:** When an analyst asks a question, the LLM classifies the intent (e.g., `failed_logins_trend`) and returns a JSON payload. We also engineered a custom `help` intent to guide users on how to interact with the system.
* **Defensive JSON Parsing:** Because LLMs often hallucinate markdown formatting, we implemented custom string-stripping logic to defensively parse the LLM's raw output, ensuring the application never crashes due to unexpected markdown fences (```json).
* **Graceful Failure Handling:** We implemented strict empty-dataframe checks (`if df.empty:`) before chart generation. If a user filters out data, the agent fails gracefully with a human-readable message rather than throwing a Pandas rendering error.
* **Dynamic Generation:** Python intercepts the validated JSON intent, queries the cleaned datasets, and dynamically renders the correct Plotly chart (Line vs. Bar) alongside an AI-generated textual summary.

---

## 5. Conclusion
By treating the data like a real corporate consulting sprint, we successfully transitioned from chaotic, messy logs to a governed analytics pipeline, culminating in a highly interactive, AI-powered Cyber-Command interface. 
