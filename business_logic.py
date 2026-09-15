import pandas as pd
import numpy as np

def evaluate_security_rules(dim_master, fact_iam, fact_endpoint, fact_firewall, session_correlations=None):
    """
    Evaluates explicit cybersecurity detection rules across the integrated model:
    - Rule 1: High failed IAM logins (>= 5 failed attempts)
    - Rule 2: Repeated MFA failures (>= 2)
    - Rule 3: High/Critical severity endpoint detection
    - Rule 4: Repeated firewall deny activity on same host (>= 10 denies)
    - Rule 5: Multi-system correlation: User with both failed logins and endpoint alerts
    - Rule 6: Cross-system correlation: IAM and Firewall linked via session or host proximity
    - Rule 7: Host under multi-vector attack (concurrent Endpoint, IAM, and Firewall blocks)
    """
    findings = {}

    # Rule 1: High Failed Logins
    iam_fails = fact_iam[fact_iam['event_category'] == 'login_failed'].groupby('user_id').size().reset_index(name='fail_count')
    rule1 = iam_fails[iam_fails['fail_count'] >= 5].merge(dim_master[['user_id', 'full_name', 'department']], on='user_id', how='left')
    findings['rule1_repeated_failed_logins'] = rule1.sort_values(by='fail_count', ascending=False)

    # Rule 2: Repeated MFA Failures
    mfa_fails = fact_iam[fact_iam['event_category'] == 'mfa_failure'].groupby('user_id').size().reset_index(name='mfa_fail_count')
    rule2 = mfa_fails[mfa_fails['mfa_fail_count'] >= 2].merge(dim_master[['user_id', 'full_name', 'department']], on='user_id', how='left')
    findings['rule2_repeated_mfa_failures'] = rule2.sort_values(by='mfa_fail_count', ascending=False)

    # Rule 3: High/Critical Endpoint Detections
    rule3 = fact_endpoint[fact_endpoint['severity'].isin(['CRITICAL', 'HIGH'])].copy()
    rule3 = rule3.merge(dim_master[['user_id', 'full_name', 'department']], on='user_id', how='left')
    findings['rule3_critical_endpoint_alerts'] = rule3

    # Rule 4: Repeated Firewall Denies by Host
    fw_denies = fact_firewall[fact_firewall['action'] == 'deny'].groupby('hostname_norm').size().reset_index(name='deny_count')
    rule4 = fw_denies[fw_denies['deny_count'] >= 10].sort_values(by='deny_count', ascending=False)
    findings['rule4_repeated_firewall_denies'] = rule4

    # Rule 5: Multi-System IAM + Endpoint on Same User
    rule5 = pd.merge(
        iam_fails[['user_id', 'fail_count']],
        fact_endpoint.groupby('user_id').size().reset_index(name='alert_count'),
        on='user_id', how='inner'
    ).merge(dim_master[['user_id', 'full_name', 'department', 'status_norm']], on='user_id', how='left')
    findings['rule5_iam_endpoint_multisystem'] = rule5.sort_values(by=['fail_count', 'alert_count'], ascending=[False, False])

    # Rule 6: IAM + Firewall Correlated Sessions
    if session_correlations is not None and not session_correlations.empty:
        findings['rule6_correlated_sessions'] = session_correlations
    else:
        findings['rule6_correlated_sessions'] = pd.DataFrame()

    # Rule 7: Tri-System Host Threat Signals
    host_fails = fact_iam[fact_iam['event_category'] == 'login_failed'].groupby('hostname_norm').size().reset_index(name='host_fails')
    host_alerts = fact_endpoint.groupby('hostname_norm').size().reset_index(name='host_alerts')
    host_denies = fact_firewall[fact_firewall['action'] == 'deny'].groupby('hostname_norm').size().reset_index(name='host_denies')

    rule7 = host_fails.merge(host_alerts, on='hostname_norm', how='inner').merge(host_denies, on='hostname_norm', how='inner')
    rule7 = rule7.sort_values(by=['host_alerts', 'host_denies', 'host_fails'], ascending=[False, False, False])
    findings['rule7_multivector_host_threats'] = rule7

    # Rule 8: Endpoint Alerts with Impossible Resolution Timestamps
    if 'impossible_resolution_flag' in fact_endpoint.columns:
        rule8 = fact_endpoint[fact_endpoint['impossible_resolution_flag'] == True].copy()
    elif 'detected_timestamp' in fact_endpoint.columns and 'resolved_timestamp' in fact_endpoint.columns:
        rule8 = fact_endpoint[
            fact_endpoint['resolved_timestamp'].notna() & 
            fact_endpoint['detected_timestamp'].notna() & 
            (fact_endpoint['resolved_timestamp'] < fact_endpoint['detected_timestamp'])
        ].copy()
    else:
        rule8 = pd.DataFrame()
    findings['rule8_impossible_resolution_alerts'] = rule8

    return findings

