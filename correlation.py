import pandas as pd
import numpy as np

def correlate_iam_firewall_sessions(fact_iam, fact_firewall):
    """
    Correlates IAM events and Firewall events via session_id_norm.
    Matches where session_id is valid and present in both systems.
    Calculates time delta between authentication and network action.
    """
    iam_valid = fact_iam[fact_iam['session_id_norm'].notna()].copy()
    fw_valid = fact_firewall[fact_firewall['session_id_norm'].notna()].copy()

    # Merge on session_id_norm
    m = pd.merge(
        iam_valid[[
            'event_id', 'timestamp', 'user_id', 'hostname_norm', 
            'session_id_norm', 'event_category', 'risk_score', 'source_ip'
        ]],
        fw_valid[[
            'log_id', 'timestamp', 'hostname_norm', 'session_id_norm', 
            'action', 'threat_flag', 'protocol', 'dst_ip', 'dst_port', 'rule_name'
        ]],
        on='session_id_norm',
        suffixes=('_iam', '_fw'),
        how='inner'
    )

    if not m.empty:
        # Calculate time difference in seconds and minutes
        m['time_diff_sec'] = (m['timestamp_fw'] - m['timestamp_iam']).dt.total_seconds()
        m['time_diff_abs_sec'] = m['time_diff_sec'].abs()
        m['same_host'] = m['hostname_norm_iam'] == m['hostname_norm_fw']
        m['correlation_type'] = 'SESSION_MATCH'
        
        # Sort by closest time difference
        m = m.sort_values(by='time_diff_abs_sec', ascending=True)

    return m

def correlate_iam_firewall_proximity(fact_iam, fact_firewall, tolerance_minutes=30):
    """
    Correlates IAM events and Firewall events on the SAME HOST within a defined
    temporal proximity tolerance window (default: 30 minutes).
    Uses pandas merge_asof for high-performance nearest-neighbor time correlation.
    """
    iam_clean = fact_iam[fact_iam['hostname_norm'].notna() & fact_iam['timestamp'].notna()].copy()
    fw_clean = fact_firewall[fact_firewall['hostname_norm'].notna() & fact_firewall['timestamp'].notna()].copy()

    if iam_clean.empty or fw_clean.empty:
        return pd.DataFrame()

    # merge_asof requires strictly sorted timestamps
    iam_clean = iam_clean.sort_values('timestamp')
    fw_clean = fw_clean.sort_values('timestamp')

    tolerance = pd.Timedelta(minutes=tolerance_minutes)

    # Perform nearest asof merge on timestamp grouped by hostname_norm
    asof_merged = pd.merge_asof(
        iam_clean[[
            'event_id', 'timestamp', 'user_id', 'hostname_norm', 
            'session_id_norm', 'event_category', 'risk_score', 'department'
        ]],
        fw_clean[[
            'log_id', 'timestamp', 'hostname_norm', 'session_id_norm', 
            'action', 'threat_flag', 'protocol', 'dst_ip', 'dst_port', 'rule_name'
        ]],
        on='timestamp',
        by='hostname_norm',
        tolerance=tolerance,
        direction='nearest',
        suffixes=('_iam', '_fw')
    )

    # Filter only records that found a match
    matched = asof_merged[asof_merged['log_id'].notna()].copy()
    if not matched.empty:
        matched['time_diff_sec'] = (matched['timestamp'] - matched['timestamp']).dt.total_seconds()
        matched['correlation_type'] = f'TEMPORAL_PROXIMITY_{tolerance_minutes}M'
        matched['same_host'] = True

    return matched

def get_cross_system_summary(fact_iam, fact_endpoint, fact_firewall):
    """
    Generates high-level cross-system correlation metrics:
    - Host overlap across all 3 telemetry sources
    - User overlap between IAM and Endpoint
    - Multi-signal correlated entities
    """
    iam_hosts = set(fact_iam['hostname_norm'].dropna())
    ep_hosts = set(fact_endpoint['hostname_norm'].dropna())
    fw_hosts = set(fact_firewall['hostname_norm'].dropna())

    all_three_hosts = iam_hosts.intersection(ep_hosts).intersection(fw_hosts)
    
    iam_users = set(fact_iam['user_id'].dropna())
    ep_users = set(fact_endpoint['user_id'].dropna())
    users_with_alerts = iam_users.intersection(ep_users)

    # Find users with both failed logins and critical endpoint alerts
    failed_login_users = set(fact_iam[fact_iam['event_category'].isin(['login_failed', 'mfa_failure'])]['user_id'].dropna())
    crit_alert_users = set(fact_endpoint[fact_endpoint['severity'].isin(['CRITICAL', 'HIGH'])]['user_id'].dropna())
    high_threat_users = failed_login_users.intersection(crit_alert_users)

    # Find hosts with both firewall blocks and endpoint alerts
    blocked_hosts = set(fact_firewall[fact_firewall['action'] == 'deny']['hostname_norm'].dropna())
    ep_alert_hosts = set(fact_endpoint['hostname_norm'].dropna())
    threat_hosts = blocked_hosts.intersection(ep_alert_hosts)

    return {
        'total_tri_system_hosts': len(all_three_hosts),
        'total_iam_endpoint_users': len(users_with_alerts),
        'high_threat_insider_users': len(high_threat_users),
        'high_threat_hosts': len(threat_hosts),
        'tri_system_host_list': list(all_three_hosts),
        'high_threat_user_list': list(high_threat_users)
    }
