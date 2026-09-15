import pandas as pd
import numpy as np

def get_kpi_metrics(filtered_user_risk, fact_iam, fact_endpoint, fact_firewall, filtered_master):
    """
    Computes top-level Command Center KPI cards.
    """
    critical_users = len(filtered_user_risk[filtered_user_risk['risk_level'] == 'CRITICAL'])
    high_users = len(filtered_user_risk[filtered_user_risk['risk_level'] == 'HIGH'])
    
    # Filter facts by selected departments/users
    valid_uids = set(filtered_master['user_id'].dropna())
    valid_hosts = set(filtered_master['hostname_norm'].dropna())

    f_iam = fact_iam[fact_iam['user_id'].isin(valid_uids)]
    failed_logins = int((f_iam['event_category'] == 'login_failed').sum())
    mfa_failures = int((f_iam['event_category'] == 'mfa_failure').sum())

    f_ep = fact_endpoint[fact_endpoint['user_id'].isin(valid_uids)]
    critical_alerts = int((f_ep['severity'] == 'CRITICAL').sum())
    total_alerts = len(f_ep)

    f_fw = fact_firewall[fact_firewall['hostname_norm'].isin(valid_hosts)]
    firewall_denies = int((f_fw['action'] == 'deny').sum())

    avg_risk = float(filtered_user_risk['risk_score'].mean()) if not filtered_user_risk.empty else 0.0

    return {
        'critical_users': critical_users,
        'high_users': high_users,
        'failed_logins': failed_logins,
        'mfa_failures': mfa_failures,
        'critical_alerts': critical_alerts,
        'total_alerts': total_alerts,
        'firewall_denies': firewall_denies,
        'avg_risk_score': round(avg_risk, 1)
    }

def get_security_activity_timeline(fact_iam, fact_endpoint, fact_firewall, valid_uids, valid_hosts):
    """
    Aggregates security activities by date across all 3 systems for unified timeline.
    """
    # 1. IAM failed logins
    iam_f = fact_iam[fact_iam['user_id'].isin(valid_uids) & fact_iam['timestamp'].notna()].copy()
    iam_fails = iam_f[iam_f['event_category'].isin(['login_failed', 'mfa_failure'])].copy()
    iam_fails['date'] = iam_fails['timestamp'].dt.date
    iam_trend = iam_fails.groupby('date').size().reset_index(name='Failed Logins')

    # 2. Endpoint Alerts
    ep_f = fact_endpoint[fact_endpoint['user_id'].isin(valid_uids) & fact_endpoint['detected_timestamp'].notna()].copy()
    ep_f['date'] = ep_f['detected_timestamp'].dt.date
    ep_trend = ep_f.groupby('date').size().reset_index(name='Endpoint Alerts')

    # 3. Firewall Denies
    fw_f = fact_firewall[fact_firewall['hostname_norm'].isin(valid_hosts) & fact_firewall['timestamp'].notna()].copy()
    fw_denies = fw_f[fw_f['action'] == 'deny'].copy()
    fw_denies['date'] = fw_denies['timestamp'].dt.date
    fw_trend = fw_denies.groupby('date').size().reset_index(name='Firewall Blocks')

    # Combine into unified date-indexed dataframe
    timeline = pd.merge(iam_trend, ep_trend, on='date', how='outer')
    timeline = pd.merge(timeline, fw_trend, on='date', how='outer').fillna(0)
    timeline = timeline.sort_values('date')
    return timeline

def get_department_risk_summary(filtered_user_risk):
    """
    Aggregates risk score and high-risk identity distribution across departments.
    """
    dept_summary = filtered_user_risk.groupby('department').agg(
        total_users=('user_id', 'count'),
        critical_users=('risk_level', lambda x: (x == 'CRITICAL').sum()),
        high_users=('risk_level', lambda x: (x == 'HIGH').sum()),
        avg_risk=('risk_score', 'mean'),
        total_failed_logins=('failed_logins', 'sum'),
        total_alerts=('total_endpoint_alerts', 'sum')
    ).reset_index()

    dept_summary['high_or_crit_users'] = dept_summary['critical_users'] + dept_summary['high_users']
    dept_summary['avg_risk'] = dept_summary['avg_risk'].round(1)
    return dept_summary.sort_values(by=['high_or_crit_users', 'avg_risk'], ascending=[False, False])

def get_security_signal_breakdown(kpis, total_correlations):
    """
    Returns breakdown of total signals across IAM, Endpoint, Firewall, and Correlation.
    """
    data = [
        {'Source': 'IAM Failures', 'Count': kpis['failed_logins'] + kpis['mfa_failures']},
        {'Source': 'Endpoint Alerts', 'Count': kpis['total_alerts']},
        {'Source': 'Firewall Blocks', 'Count': kpis['firewall_denies']},
        {'Source': 'Correlated Events', 'Count': total_correlations}
    ]
    return pd.DataFrame(data)

def generate_security_insights(user_risk_df, host_risk_df, dept_summary, total_correlations):
    """
    Synthesizes executive analytical insights based on actual underlying numbers.
    """
    insights = []

    # Dept insight
    if not dept_summary.empty:
        top_dept = dept_summary.iloc[0]
        insights.append(
            f"**Department Risk Concentration**: **{top_dept['department']}** exhibits highest threat density with "
            f"**{int(top_dept['high_or_crit_users'])}** High/Critical risk identities and an average risk score of **{top_dept['avg_risk']}**."
        )

    # Top User insight
    if not user_risk_df.empty:
        top_user = user_risk_df.iloc[0]
        insights.append(
            f"**Top At-Risk Identity**: **{top_user['user_id']}** ({top_user['full_name']} - {top_user['department']}) "
            f"has reached **{top_user['risk_level']}** risk (Score: {top_user['risk_score']}) due to {top_user['main_reason']}."
        )

    # Top Host insight
    if not host_risk_df.empty:
        top_host = host_risk_df.iloc[0]
        insights.append(
            f"**Most Compromised Endpoint**: **{top_host['hostname_norm']}** recorded highest hostile exposure "
            f"with a host risk score of **{top_host['risk_score']}** ({top_host['main_reason']})."
        )

    # Correlation insight
    if total_correlations > 0:
        insights.append(
            f"**Cross-System Lateral Correlation**: Detected **{total_correlations}** cross-system events "
            f"bridging IAM authentication with network firewall perimeter alerts via session identifiers and host temporal proximity."
        )

    return insights
