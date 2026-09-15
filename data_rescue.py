import pandas as pd
import numpy as np
import json
import re

# ==========================================
# DATATHON GATE 2: DATA RESCUE & ENGINEERING
# ==========================================
# DECISION: We chose to build a modular Python pipeline instead of a Jupyter Notebook 
# for better reproducibility, version control, and production readiness.

def standardize_user_id(uid):
    """
    Standardize user_id formats: EMP12345, emp12345, EMP-12345, EMP 12345, 12345 -> EMP12345
    DECISION: Because the datasets originate from different systems (IAM, Endpoint), 
    the foreign keys (user_id) are highly heterogeneous. We use a regex to strip all 
    non-numeric characters and explicitly prepend 'EMP' to guarantee a perfect 1:1 join.
    """
    if pd.isna(uid):
        return uid
    # Extract only digits and prepend 'EMP'
    digits = re.sub(r'\D', '', str(uid))
    if digits:
        return f"EMP{digits}"
    return uid

def standardize_department(dept):
    """
    Standardize department names to a consistent Title Case format.
    DECISION: Free-text fields lead to categorical fragmentation (e.g. 'it', 'information tech').
    We implemented a dictionary mapping to force these anomalies into a strict, unified ontology 
    so our dashboard filters group the data correctly.
    """
    if pd.isna(dept):
        return dept
    dept = str(dept).strip().lower()
    
    mapping = {
        'it': 'IT',
        'information tech': 'IT',
        'sales team': 'Sales',
        'sales': 'Sales',
        'legal': 'Legal',
        'rnd': 'R&D',
        'r&d': 'R&D',
        'finance dept': 'Finance',
        'finance': 'Finance',
        'marketing': 'Marketing',
        'support': 'Support',
        'call center': 'Call Center',
        'compliance': 'Compliance',
        'operations': 'Operations',
        'supply chain': 'Supply Chain'
    }
    return mapping.get(dept, dept.title())

def parse_dates(df, columns):
    """
    Parse mixed timestamp formats to standard datetime (UTC).
    DECISION: The raw telemetry contains conflicting timezone and regional date formats 
    (e.g., DD/MM/YYYY vs MM-DD-YYYY). We utilize pd.to_datetime with format='mixed' 
    and dayfirst=True to intelligently parse these without dropping rows.
    """
    for col in columns:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce', format='mixed', dayfirst=True)
    return df

def normalize_fw_actions(action):
    """
    DECISION: Firewall rules were written by different admins over time. We map all 
    permutations of allow/deny into a strictly binary classification for easier charting.
    """
    if pd.isna(action):
        return action
    action = str(action).strip().lower()
    allow_list = ['permit', 'pass', 'allow']
    deny_list = ['deny', 'block', 'drop']
    
    if action in allow_list:
        return 'allow'
    if action in deny_list:
        return 'deny'
    return 'unknown'

def normalize_iam_events(event):
    """
    DECISION: IAM logs contain too many verbose system messages. We reduce the dimensionality 
    by grouping them into 3 high-level categories ('login_success', 'login_failed', 'other') 
    which directly answers the core business questions about compromised accounts.
    """
    if pd.isna(event):
        return 'other'
    event = str(event).strip().lower()
    success = ['logon_success', 'success_login', 'login_success', 'auth_success', 
               'successful login', 'sso_success']
    failed = ['mfa_failed', 'failed_login', 'invalid_credentials', 'login failed', 
              'logon_failure', 'auth_failed', 'failed logon']
    
    if event in success:
        return 'login_success'
    if event in failed:
        return 'login_failed'
    return 'other'

def normalize_severity(sev):
    """
    DECISION: Standardize Endpoint alert severities into 4 distinct tiers so they 
    can be properly color-coded (Red/Yellow/Orange) in the UI.
    """
    if pd.isna(sev):
        return 'UNKNOWN'
    sev = str(sev).strip().lower()
    crit = ['severe', 'critical', 'crit', 'p1', 'major']
    high = ['high', 'h', 'p2']
    med = ['medium', 'm', 'p3', 'moderate']
    low = ['low', 'l', 'p4', 'minor']
    
    if sev in crit: return 'CRITICAL'
    if sev in high: return 'HIGH'
    if sev in med: return 'MEDIUM'
    if sev in low: return 'LOW'
    return 'UNKNOWN'

def clean_ip(ip):
    """
    DECISION: Truncated or invalid IPs will break geospatial mapping. We apply a 
    strict Regex check and nullify non-conforming IPs to prevent mapping errors.
    """
    if pd.isna(ip):
        return ip
    ip = str(ip).strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return ip
    return np.nan

def clean_risk_score(score):
    """
    DECISION: Risk scores are corrupted with text strings like '78/100' or 'High'. 
    We extract the pure numeric float so we can calculate the 'Average Risk Score' KPI.
    """
    if pd.isna(score):
        return np.nan
    score = str(score).strip().lower()
    if 'high' in score: return 90.0
    if 'med' in score: return 50.0
    if 'low' in score: return 10.0
    
    match = re.search(r'(\d+)', score)
    if match:
        return float(match.group(1))
    return np.nan

def main():
    print("Starting Data Rescue & Cleaning Pipeline...")

    # ==========================
    # 1. Identity Asset Master
    # ==========================
    print("Cleaning Identity Asset Master...")
    df_master = pd.read_csv('track2_identity_asset_master.csv')
    raw_len = len(df_master)
    df_master['user_id'] = df_master['user_id'].apply(standardize_user_id)
    df_master['department'] = df_master['department'].apply(standardize_department)
    
    # DECISION: Duplicates artificially inflate user counts. We drop them aggressively.
    df_master.drop_duplicates(inplace=True)
    df_master = parse_dates(df_master, ['hire_date', 'termination_date'])
    df_master.to_csv('cleaned_identity_asset_master.csv', index=False)
    print(f"Master Data: {raw_len} rows -> {len(df_master)} cleaned rows")

    # ==========================
    # 2. Firewall Logs
    # ==========================
    print("Cleaning Firewall Logs...")
    df_fw = pd.read_csv('track2_firewall_logs.csv')
    raw_len = len(df_fw)
    df_fw['action'] = df_fw['action'].apply(normalize_fw_actions)
    df_fw['src_ip'] = df_fw['src_ip'].apply(clean_ip)
    df_fw['dst_ip'] = df_fw['dst_ip'].apply(clean_ip)
    
    # DECISION: Ports must be numeric. Invalid text ('unknown') is coerced to NaN.
    df_fw['src_port'] = pd.to_numeric(df_fw['src_port'], errors='coerce')
    df_fw['dst_port'] = pd.to_numeric(df_fw['dst_port'], errors='coerce')
    
    # DECISION: Bytes columns contain text ('1024 bytes'). We extract the raw digits to allow aggregations.
    df_fw['bytes_sent'] = df_fw['bytes_sent'].astype(str).str.extract(r'(\d+)').astype(float)
    df_fw['bytes_received'] = df_fw['bytes_received'].astype(str).str.extract(r'(\d+)').astype(float)
    df_fw = parse_dates(df_fw, ['timestamp'])
    df_fw.drop_duplicates(inplace=True)
    df_fw.to_csv('cleaned_firewall_logs.csv', index=False)
    print(f"Firewall Logs: {raw_len} rows -> {len(df_fw)} cleaned rows")

    # ==========================
    # 3. IAM Audit Trail
    # ==========================
    print("Cleaning IAM Audit Trail...")
    df_iam = pd.read_json('track2_iam_audit_trail.json')
    raw_len = len(df_iam)
    df_iam['user_id'] = df_iam['user_id'].apply(standardize_user_id)
    df_iam['department'] = df_iam['department'].apply(standardize_department)
    df_iam['event_category'] = df_iam['event_type'].apply(normalize_iam_events)
    df_iam['risk_score'] = df_iam['risk_score'].apply(clean_risk_score)
    df_iam['source_ip'] = df_iam['source_ip'].apply(clean_ip)
    df_iam = parse_dates(df_iam, ['timestamp'])
    df_iam.drop_duplicates(inplace=True)
    df_iam.to_csv('cleaned_iam_audit_trail.csv', index=False)
    print(f"IAM Logs: {raw_len} rows -> {len(df_iam)} cleaned rows")

    # ==========================
    # 4. Endpoint Alerts
    # ==========================
    print("Cleaning Endpoint Alerts...")
    df_alerts = pd.read_excel('track2_endpoint_alerts.xlsx')
    raw_len = len(df_alerts)
    df_alerts['user_id'] = df_alerts['user_id'].apply(standardize_user_id)
    df_alerts['severity'] = df_alerts['severity'].apply(normalize_severity)
    df_alerts = parse_dates(df_alerts, ['detected_timestamp', 'resolved_timestamp'])
    df_alerts.drop_duplicates(inplace=True)
    df_alerts.to_csv('cleaned_endpoint_alerts.csv', index=False)
    print(f"Endpoint Alerts: {raw_len} rows -> {len(df_alerts)} cleaned rows")

    print("Pipeline Complete! Cleaned datasets exported to CSV.")

if __name__ == "__main__":
    main()
