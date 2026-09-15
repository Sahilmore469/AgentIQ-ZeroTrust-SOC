import pandas as pd
import numpy as np
import json
import re
from transformations import (
    standardize_user_id,
    standardize_hostname,
    standardize_session_id,
    standardize_department,
    robust_parse_timestamps,
    normalize_fw_actions,
    normalize_threat_flag,
    normalize_iam_events,
    normalize_severity,
    clean_ip,
    clean_risk_score,
    clean_port,
    normalize_status,
    normalize_protocol,
    normalize_endpoint_status
)

# ==============================================================================
# DATATHON GATE 2: DATA RESCUE & ENGINEERING PIPELINE
# ==============================================================================
# DECISION: We engineered an automated, robust data cleaning pipeline that ensures
# high data integrity, standardizes keys across all telemetry systems, resolves
# mixed timestamp anomalies (including Unix epoch recovery), normalizes protocols/statuses,
# and eliminates duplicate records without sacrificing raw telemetry observations.

def main():
    print("Starting Comprehensive Data Rescue & Cleaning Pipeline...")

    # ==========================
    # 1. Identity Asset Master
    # ==========================
    # DECISION: Standardize user IDs and hostnames to serve as canonical star schema dimension.
    # Deduplicate strictly on user_id to prevent any downstream row multiplication.
    print("Cleaning Identity Asset Master...")
    df_master = pd.read_csv('track2_identity_asset_master.csv')
    raw_len_master = len(df_master)
    
    df_master['user_id'] = df_master['user_id'].apply(standardize_user_id)
    df_master = df_master[df_master['user_id'].notna()].copy()
    df_master['department'] = df_master['department'].apply(standardize_department)
    df_master['status_norm'] = df_master['status'].apply(normalize_status)
    df_master['hostname_norm'] = df_master['hostname'].apply(standardize_hostname)
    
    # Deduplicate strictly on user_id
    df_master = df_master.drop_duplicates(subset=['user_id'], keep='first')
    if 'hire_date' in df_master.columns:
        df_master['hire_date'] = robust_parse_timestamps(df_master['hire_date'])
    if 'termination_date' in df_master.columns:
        df_master['termination_date'] = robust_parse_timestamps(df_master['termination_date'])
    
    df_master.to_csv('cleaned_identity_asset_master.csv', index=False)
    print(f"Master Data: {raw_len_master} rows -> {len(df_master)} cleaned rows")

    # Build lookup dictionaries from master for intelligent imputation
    master_dept_map = df_master.set_index('user_id')['department'].to_dict()
    master_host_map = df_master.dropna(subset=['hostname_norm']).set_index('user_id')['hostname_norm'].to_dict()

    # ==========================
    # 2. Firewall Logs
    # ==========================
    # DECISION: Normalize firewall actions to binary allow/deny, standardize protocol numbers (6->TCP, 17->UDP, 1->ICMP),
    # clean invalid IPs and ports, extract numeric byte counts, and parse mixed timestamps.
    print("Cleaning Firewall Logs...")
    df_fw = pd.read_csv('track2_firewall_logs.csv')
    raw_len_fw = len(df_fw)
    
    df_fw['hostname_norm'] = df_fw['hostname'].apply(standardize_hostname)
    df_fw['session_id_norm'] = df_fw['session_id'].apply(standardize_session_id)
    df_fw['action'] = df_fw['action'].apply(normalize_fw_actions)
    df_fw['protocol'] = df_fw['protocol'].apply(normalize_protocol)
    df_fw['threat_flag'] = df_fw['threat_flag'].apply(normalize_threat_flag)
    df_fw['src_ip'] = df_fw['src_ip'].apply(clean_ip)
    df_fw['dst_ip'] = df_fw['dst_ip'].apply(clean_ip)
    df_fw['src_port'] = df_fw['src_port'].apply(clean_port)
    df_fw['dst_port'] = df_fw['dst_port'].apply(clean_port)
    df_fw['bytes_sent'] = df_fw['bytes_sent'].astype(str).str.extract(r'(\d+)').astype(float)
    df_fw['bytes_received'] = df_fw['bytes_received'].astype(str).str.extract(r'(\d+)').astype(float)
    df_fw['timestamp'] = robust_parse_timestamps(df_fw['timestamp'])
    
    if 'log_id' in df_fw.columns:
        df_fw = df_fw.drop_duplicates(subset=['log_id'], keep='first')
    else:
        df_fw = df_fw.drop_duplicates()
    df_fw.to_csv('cleaned_firewall_logs.csv', index=False)
    print(f"Firewall Logs: {raw_len_fw} rows -> {len(df_fw)} cleaned rows")

    # ==========================
    # 3. IAM Audit Trail
    # ==========================
    # DECISION: Recover missing departments and hostnames by mapping user_id to Identity Master.
    # Normalize event types to login_success, login_failed, mfa_failure, other. Validate risk scores and IPs.
    print("Cleaning IAM Audit Trail...")
    df_iam = pd.read_json('track2_iam_audit_trail.json')
    raw_len_iam = len(df_iam)
    
    df_iam['user_id'] = df_iam['user_id'].apply(standardize_user_id)
    df_iam['hostname_norm'] = df_iam['hostname'].apply(standardize_hostname)
    # Backfill missing IAM hostnames from master if user is known
    df_iam['hostname_norm'] = df_iam['hostname_norm'].fillna(df_iam['user_id'].map(master_host_map))
    df_iam['session_id_norm'] = df_iam['session_id'].apply(standardize_session_id)
    
    df_iam['department'] = df_iam['department'].apply(standardize_department)
    # Impute unknown/missing department from Master
    unknown_dept_mask = df_iam['department'].isin(['Unknown', 'unknown', None]) | df_iam['department'].isna()
    df_iam.loc[unknown_dept_mask, 'department'] = df_iam.loc[unknown_dept_mask, 'user_id'].map(master_dept_map).fillna('Unknown')

    df_iam['event_category'] = df_iam['event_type'].apply(normalize_iam_events)
    df_iam['risk_score'] = df_iam['risk_score'].apply(clean_risk_score)
    df_iam['source_ip'] = df_iam['source_ip'].apply(clean_ip)
    df_iam['timestamp'] = robust_parse_timestamps(df_iam['timestamp'])
    
    if 'event_id' in df_iam.columns:
        df_iam = df_iam.drop_duplicates(subset=['event_id'], keep='first')
    else:
        df_iam = df_iam.drop_duplicates()
    df_iam.to_csv('cleaned_iam_audit_trail.csv', index=False)
    print(f"IAM Logs: {raw_len_iam} rows -> {len(df_iam)} cleaned rows")

    # ==========================
    # 4. Endpoint Alerts
    # ==========================
    # DECISION: Standardize user IDs and hostnames (backfilling from master where missing),
    # normalize alert severities and workflow statuses, and flag impossible resolution timestamps.
    print("Cleaning Endpoint Alerts...")
    try:
        df_alerts = pd.read_excel('track2_endpoint_alerts.xlsx')
    except Exception:
        df_alerts = pd.read_csv('cleaned_endpoint_alerts.csv')
        
    raw_len_alerts = len(df_alerts)
    df_alerts['user_id'] = df_alerts['user_id'].apply(standardize_user_id)
    df_alerts['hostname_norm'] = df_alerts['hostname'].apply(standardize_hostname)
    # Backfill missing Endpoint hostnames from master if user is known
    df_alerts['hostname_norm'] = df_alerts['hostname_norm'].fillna(df_alerts['user_id'].map(master_host_map))
    
    df_alerts['severity'] = df_alerts['severity'].apply(normalize_severity)
    df_alerts['status_norm'] = df_alerts['status'].apply(normalize_endpoint_status)
    df_alerts['detected_timestamp'] = robust_parse_timestamps(df_alerts['detected_timestamp'])
    if 'resolved_timestamp' in df_alerts.columns:
        df_alerts['resolved_timestamp'] = robust_parse_timestamps(df_alerts['resolved_timestamp'])
        # Flag impossible timestamps where resolution precedes detection
        df_alerts['impossible_resolution_flag'] = (
            df_alerts['resolved_timestamp'].notna() & 
            df_alerts['detected_timestamp'].notna() & 
            (df_alerts['resolved_timestamp'] < df_alerts['detected_timestamp'])
        )
    else:
        df_alerts['impossible_resolution_flag'] = False
        
    if 'alert_id' in df_alerts.columns:
        df_alerts = df_alerts.drop_duplicates(subset=['alert_id'], keep='first')
    else:
        df_alerts = df_alerts.drop_duplicates()
    df_alerts.to_csv('cleaned_endpoint_alerts.csv', index=False)
    print(f"Endpoint Alerts: {raw_len_alerts} rows -> {len(df_alerts)} cleaned rows")

    print("\nData Rescue Pipeline Complete! All high-integrity CSVs exported.")

if __name__ == "__main__":
    main()

