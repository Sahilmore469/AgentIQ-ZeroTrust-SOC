import pandas as pd
import numpy as np

def calculate_user_risk_profile(dim_master, fact_iam, fact_endpoint, fact_firewall, session_correlations=None):
    """
    Computes an explainable, multi-factor risk score (0-100) for every user.
    Components:
    - Identity Risk (30%): Failed logins, MFA failures, IAM risk score
    - Endpoint Risk (30%): Alert count, Critical/High alert weights
    - Network Risk (20%): Firewall deny count on user's primary host
    - Cross-System Correlation (20%): Multi-system alerts, session correlations
    """
    # 1. Base master users
    users_df = dim_master[['user_id', 'full_name', 'department', 'status_norm', 'hostname_norm']].copy()
    
    # 2. IAM aggregations
    iam_agg = fact_iam.groupby('user_id').agg(
        total_iam_events=('event_id', 'count'),
        failed_logins=('event_category', lambda x: (x == 'login_failed').sum()),
        mfa_failures=('event_category', lambda x: (x == 'mfa_failure').sum()),
        avg_iam_risk=('risk_score', 'mean')
    ).reset_index()
    
    # 3. Endpoint aggregations
    ep_agg = fact_endpoint.groupby('user_id').agg(
        total_endpoint_alerts=('alert_id', 'count'),
        critical_alerts=('severity', lambda x: (x == 'CRITICAL').sum()),
        high_alerts=('severity', lambda x: (x == 'HIGH').sum()),
        med_alerts=('severity', lambda x: (x == 'MEDIUM').sum()),
        low_alerts=('severity', lambda x: (x == 'LOW').sum())
    ).reset_index()

    # 4. Firewall aggregations by host -> mapped to user's assigned host
    host_fw = fact_firewall.groupby('hostname_norm').agg(
        host_fw_total=('log_id', 'count'),
        host_fw_denies=('action', lambda x: (x == 'deny').sum()),
        host_threat_flags=('threat_flag', 'sum')
    ).reset_index()

    # Merge all components
    m = users_df.merge(iam_agg, on='user_id', how='left')
    m = m.merge(ep_agg, on='user_id', how='left')
    m = m.merge(host_fw, on='hostname_norm', how='left')

    # Fill NaNs with 0
    numeric_cols = [
        'total_iam_events', 'failed_logins', 'mfa_failures', 'avg_iam_risk',
        'total_endpoint_alerts', 'critical_alerts', 'high_alerts', 'med_alerts', 'low_alerts',
        'host_fw_total', 'host_fw_denies', 'host_threat_flags'
    ]
    for c in numeric_cols:
        m[c] = m[c].fillna(0)

    # 5. Check session correlations per user
    if session_correlations is not None and not session_correlations.empty:
        corr_users = set(session_correlations['user_id'].dropna())
        m['has_session_correlation'] = m['user_id'].isin(corr_users)
    else:
        m['has_session_correlation'] = False

    # 6. Score Calculation (Deterministic & Explainable)
    # Identity Component (max 30 pts):
    # failed_logins: up to 15 pts (min(failed_logins * 2, 15))
    # mfa_failures: up to 10 pts (min(mfa_failures * 5, 10))
    # avg_iam_risk: up to 5 pts ((avg_iam_risk / 100) * 5)
    id_score = np.minimum(m['failed_logins'] * 2.0, 15.0) + \
               np.minimum(m['mfa_failures'] * 5.0, 10.0) + \
               ((m['avg_iam_risk'] / 100.0) * 5.0)

    # Endpoint Component (max 30 pts):
    # critical_alerts: 15 pts each (capped at 20)
    # high_alerts: 5 pts each (capped at 10)
    ep_score = np.minimum(m['critical_alerts'] * 15.0, 20.0) + \
               np.minimum(m['high_alerts'] * 5.0, 10.0)

    # Network Component (max 20 pts):
    # host_fw_denies: up to 15 pts (min(host_fw_denies * 0.75, 15))
    # host_threat_flags: up to 5 pts (min(host_threat_flags * 2.5, 5))
    net_score = np.minimum(m['host_fw_denies'] * 0.75, 15.0) + \
                np.minimum(m['host_threat_flags'] * 2.5, 5.0)

    # Cross-System Correlation Component (max 20 pts):
    # Multi-system signal: failed logins > 0 AND endpoint alerts > 0 (10 pts)
    # Terminated user still active (5 pts)
    # Session-level correlation (5 pts)
    cross_score = np.where((m['failed_logins'] > 0) & (m['total_endpoint_alerts'] > 0), 10.0, 0.0) + \
                  np.where((m['status_norm'] == 'Terminated') & (m['total_iam_events'] > 0), 5.0, 0.0) + \
                  np.where(m['has_session_correlation'], 5.0, 0.0)

    raw_score = id_score + ep_score + net_score + cross_score
    m['risk_score'] = np.clip(np.round(raw_score, 1), 0.0, 100.0)

    # Risk Levels
    conditions = [
        (m['risk_score'] >= 80.0),
        (m['risk_score'] >= 60.0),
        (m['risk_score'] >= 35.0)
    ]
    choices = ['CRITICAL', 'HIGH', 'MEDIUM']
    m['risk_level'] = np.select(conditions, choices, default='LOW')

    # Generate Human-Readable Explainable Reasons
    def generate_reasons(row):
        reasons = []
        if row['failed_logins'] > 0:
            reasons.append(f"{int(row['failed_logins'])} failed logins")
        if row['mfa_failures'] > 0:
            reasons.append(f"{int(row['mfa_failures'])} MFA failures")
        if row['critical_alerts'] > 0:
            reasons.append(f"{int(row['critical_alerts'])} CRITICAL endpoint alerts")
        if row['high_alerts'] > 0:
            reasons.append(f"{int(row['high_alerts'])} HIGH endpoint alerts")
        if row['host_fw_denies'] >= 10:
            reasons.append(f"{int(row['host_fw_denies'])} firewall denies on host")
        if row['status_norm'] == 'Terminated' and row['total_iam_events'] > 0:
            reasons.append("Terminated account generating active events")
        if row['has_session_correlation']:
            reasons.append("IAM & Firewall activity correlated through common session")
        if (row['failed_logins'] > 0) and (row['total_endpoint_alerts'] > 0):
            reasons.append("Multi-system threat: concurrent auth failures & endpoint alerts")

        if not reasons:
            return "Normal operational activity; no critical anomaly detected."
        return "; ".join(reasons)

    m['main_reason'] = m.apply(generate_reasons, axis=1)

    return m.sort_values(by='risk_score', ascending=False)

def calculate_host_risk_profile(dim_master, fact_iam, fact_endpoint, fact_firewall):
    """
    Computes an explainable risk profile for every unique hostname.
    """
    # 1. Base hosts from all sources
    all_hosts = set(dim_master['hostname_norm'].dropna()).union(
        set(fact_iam['hostname_norm'].dropna()),
        set(fact_endpoint['hostname_norm'].dropna()),
        set(fact_firewall['hostname_norm'].dropna())
    )
    hosts_df = pd.DataFrame({'hostname_norm': list(all_hosts)})

    # Map master user and dept
    master_host_map = dim_master.dropna(subset=['hostname_norm']).drop_duplicates('hostname_norm')
    hosts_df = hosts_df.merge(
        master_host_map[['hostname_norm', 'user_id', 'full_name', 'department', 'status_norm']],
        on='hostname_norm', how='left'
    )

    # IAM counts
    iam_host = fact_iam.groupby('hostname_norm').agg(
        iam_events=('event_id', 'count'),
        failed_logins=('event_category', lambda x: (x == 'login_failed').sum())
    ).reset_index()

    # Endpoint counts
    ep_host = fact_endpoint.groupby('hostname_norm').agg(
        endpoint_alerts=('alert_id', 'count'),
        critical_alerts=('severity', lambda x: (x == 'CRITICAL').sum()),
        high_alerts=('severity', lambda x: (x == 'HIGH').sum())
    ).reset_index()

    # FW counts
    fw_host = fact_firewall.groupby('hostname_norm').agg(
        firewall_events=('log_id', 'count'),
        firewall_denies=('action', lambda x: (x == 'deny').sum()),
        threat_flags=('threat_flag', 'sum')
    ).reset_index()

    m = hosts_df.merge(iam_host, on='hostname_norm', how='left')
    m = m.merge(ep_host, on='hostname_norm', how='left')
    m = m.merge(fw_host, on='hostname_norm', how='left')

    numeric_cols = [
        'iam_events', 'failed_logins', 'endpoint_alerts', 
        'critical_alerts', 'high_alerts', 'firewall_events', 
        'firewall_denies', 'threat_flags'
    ]
    for c in numeric_cols:
        m[c] = m[c].fillna(0)

    # Score calculation
    # Critical alerts (up to 35 pts)
    # Firewall denies (up to 30 pts)
    # Failed logins (up to 20 pts)
    # Threat flags (up to 15 pts)
    score = np.minimum(m['critical_alerts'] * 15.0 + m['high_alerts'] * 5.0, 35.0) + \
            np.minimum(m['firewall_denies'] * 1.5, 30.0) + \
            np.minimum(m['failed_logins'] * 3.0, 20.0) + \
            np.minimum(m['threat_flags'] * 3.0, 15.0)

    m['risk_score'] = np.clip(np.round(score, 1), 0.0, 100.0)

    conditions = [
        (m['risk_score'] >= 75.0),
        (m['risk_score'] >= 50.0),
        (m['risk_score'] >= 25.0)
    ]
    choices = ['CRITICAL', 'HIGH', 'MEDIUM']
    m['risk_level'] = np.select(conditions, choices, default='LOW')

    def generate_host_reasons(row):
        r = []
        if row['critical_alerts'] > 0:
            r.append(f"{int(row['critical_alerts'])} critical endpoint alerts")
        if row['firewall_denies'] > 0:
            r.append(f"{int(row['firewall_denies'])} blocked firewall connections")
        if row['failed_logins'] > 0:
            r.append(f"{int(row['failed_logins'])} failed authentications")
        if row['threat_flags'] > 0:
            r.append(f"{int(row['threat_flags'])} malicious threat flags raised")
        if not r:
            return "Baseline network activity; no critical host compromise identified."
        return "; ".join(r)

    m['main_reason'] = m.apply(generate_host_reasons, axis=1)

    return m.sort_values(by='risk_score', ascending=False)
