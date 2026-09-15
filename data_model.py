import pandas as pd
import numpy as np
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
    normalize_status
)

def build_dim_identity_asset(raw_master_df=None):
    """
    Builds the logical DIM_IDENTITY_ASSET dimension table.
    Guarantees unique user_id as primary key.
    Normalizes hostname, department, status, dates.
    """
    if raw_master_df is None:
        try:
            df = pd.read_csv('track2_identity_asset_master.csv')
        except FileNotFoundError:
            df = pd.read_csv('cleaned_identity_asset_master.csv')
    else:
        df = raw_master_df.copy()

    df['user_id'] = df['user_id'].apply(standardize_user_id)
    # Filter any records where user_id could not be recovered
    df = df[df['user_id'].notna()].copy()
    
    # Standardize attributes
    df['hostname_norm'] = df['hostname'].apply(standardize_hostname)
    df['department'] = df['department'].apply(standardize_department)
    df['status_norm'] = df['status'].apply(normalize_status)
    
    if 'hire_date' in df.columns:
        df['hire_date'] = robust_parse_timestamps(df['hire_date'])
    if 'termination_date' in df.columns:
        df['termination_date'] = robust_parse_timestamps(df['termination_date'])
        
    # Deduplicate strictly on user_id to ensure 1:1 join without row multiplication
    df = df.drop_duplicates(subset=['user_id'], keep='first')
    
    columns_order = [
        'user_id', 'username', 'full_name', 'department', 'role', 
        'location', 'hostname', 'hostname_norm', 'device_id', 
        'status', 'status_norm', 'hire_date', 'termination_date', 'manager_username'
    ]
    avail_cols = [c for c in columns_order if c in df.columns]
    return df[avail_cols]

def build_fact_iam(raw_iam_df=None):
    """
    Builds the logical FACT_IAM fact table.
    Contains IAM telemetry with foreign keys: user_id, hostname_norm, session_id.
    """
    if raw_iam_df is None:
        try:
            df = pd.read_json('track2_iam_audit_trail.json')
        except (FileNotFoundError, ValueError):
            df = pd.read_csv('cleaned_iam_audit_trail.csv')
    else:
        df = raw_iam_df.copy()

    df['user_id'] = df['user_id'].apply(standardize_user_id)
    df['hostname_norm'] = df['hostname'].apply(standardize_hostname)
    df['session_id_norm'] = df['session_id'].apply(standardize_session_id)
    df['department'] = df['department'].apply(standardize_department)
    df['event_category'] = df['event_type'].apply(normalize_iam_events)
    df['source_ip'] = df['source_ip'].apply(clean_ip)
    df['risk_score'] = df['risk_score'].apply(clean_risk_score)
    df['timestamp'] = robust_parse_timestamps(df['timestamp'])
    
    # Drop duplicates if any
    if 'event_id' in df.columns:
        df = df.drop_duplicates(subset=['event_id'], keep='first')
    else:
        df = df.drop_duplicates()
        
    return df

def build_fact_endpoint(raw_alerts_df=None):
    """
    Builds the logical FACT_ENDPOINT fact table.
    Foreign keys: user_id, hostname_norm.
    """
    if raw_alerts_df is None:
        try:
            df = pd.read_excel('track2_endpoint_alerts.xlsx')
        except Exception:
            df = pd.read_csv('cleaned_endpoint_alerts.csv')
    else:
        df = raw_alerts_df.copy()

    df['user_id'] = df['user_id'].apply(standardize_user_id)
    df['hostname_norm'] = df['hostname'].apply(standardize_hostname)
    df['severity'] = df['severity'].apply(normalize_severity)
    df['detected_timestamp'] = robust_parse_timestamps(df['detected_timestamp'])
    if 'resolved_timestamp' in df.columns:
        df['resolved_timestamp'] = robust_parse_timestamps(df['resolved_timestamp'])
    
    if 'alert_id' in df.columns:
        df = df.drop_duplicates(subset=['alert_id'], keep='first')
    else:
        df = df.drop_duplicates()
        
    return df

def build_fact_firewall(raw_fw_df=None):
    """
    Builds the logical FACT_FIREWALL fact table.
    Foreign keys: hostname_norm, session_id_norm.
    """
    if raw_fw_df is None:
        try:
            df = pd.read_csv('track2_firewall_logs.csv')
        except FileNotFoundError:
            df = pd.read_csv('cleaned_firewall_logs.csv')
    else:
        df = raw_fw_df.copy()

    df['hostname_norm'] = df['hostname'].apply(standardize_hostname)
    df['session_id_norm'] = df['session_id'].apply(standardize_session_id)
    df['action'] = df['action'].apply(normalize_fw_actions)
    df['threat_flag'] = df['threat_flag'].apply(normalize_threat_flag)
    df['src_ip'] = df['src_ip'].apply(clean_ip)
    df['dst_ip'] = df['dst_ip'].apply(clean_ip)
    df['src_port'] = df['src_port'].apply(clean_port)
    df['dst_port'] = df['dst_port'].apply(clean_port)
    
    # Bytes numeric extraction
    df['bytes_sent'] = df['bytes_sent'].astype(str).str.extract(r'(\d+)').astype(float)
    df['bytes_received'] = df['bytes_received'].astype(str).str.extract(r'(\d+)').astype(float)
    df['timestamp'] = robust_parse_timestamps(df['timestamp'])
    
    if 'log_id' in df.columns:
        df = df.drop_duplicates(subset=['log_id'], keep='first')
    else:
        df = df.drop_duplicates()
        
    return df

def validate_data_model(dim_master, fact_iam, fact_endpoint, fact_firewall):
    """
    Validates the star schema joins, calculating:
    - rows before and after join
    - matched and unmatched rows
    - match percentage
    - duplicate keys
    - null join keys
    """
    diagnostics = {}

    # 1. IAM -> Master on user_id
    iam_uids = fact_iam['user_id']
    master_uids = set(dim_master['user_id'].dropna())
    matched_iam = iam_uids.isin(master_uids).sum()
    diagnostics['iam_to_master'] = {
        'source_rows': len(fact_iam),
        'matched_rows': int(matched_iam),
        'unmatched_rows': int(len(fact_iam) - matched_iam),
        'match_pct': round((matched_iam / len(fact_iam)) * 100, 2) if len(fact_iam) else 0.0,
        'null_keys': int(iam_uids.isna().sum()),
        'master_key_duplicates': int(dim_master['user_id'].duplicated().sum())
    }

    # 2. Endpoint -> Master on user_id
    ep_uids = fact_endpoint['user_id']
    matched_ep_u = ep_uids.isin(master_uids).sum()
    # Also test Endpoint -> Master on hostname_norm
    ep_hosts = fact_endpoint['hostname_norm']
    master_hosts = set(dim_master['hostname_norm'].dropna())
    matched_ep_h = ep_hosts.isin(master_hosts).sum()
    diagnostics['endpoint_to_master'] = {
        'source_rows': len(fact_endpoint),
        'matched_user_rows': int(matched_ep_u),
        'match_user_pct': round((matched_ep_u / len(fact_endpoint)) * 100, 2) if len(fact_endpoint) else 0.0,
        'matched_host_rows': int(matched_ep_h),
        'match_host_pct': round((matched_ep_h / len(fact_endpoint)) * 100, 2) if len(fact_endpoint) else 0.0,
        'null_user_keys': int(ep_uids.isna().sum()),
        'null_host_keys': int(ep_hosts.isna().sum())
    }

    # 3. Firewall -> Master on hostname_norm
    fw_hosts = fact_firewall['hostname_norm']
    matched_fw_h = fw_hosts.isin(master_hosts).sum()
    diagnostics['firewall_to_master'] = {
        'source_rows': len(fact_firewall),
        'matched_rows': int(matched_fw_h),
        'unmatched_rows': int(len(fact_firewall) - matched_fw_h),
        'match_pct': round((matched_fw_h / len(fact_firewall)) * 100, 2) if len(fact_firewall) else 0.0,
        'null_keys': int(fw_hosts.isna().sum())
    }

    return diagnostics
