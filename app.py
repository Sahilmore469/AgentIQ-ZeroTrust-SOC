import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from data_model import (
    build_dim_identity_asset,
    build_fact_iam,
    build_fact_endpoint,
    build_fact_firewall,
    validate_data_model
)
from correlation import (
    correlate_iam_firewall_sessions,
    correlate_iam_firewall_proximity,
    get_cross_system_summary
)
from risk_scoring import (
    calculate_user_risk_profile,
    calculate_host_risk_profile
)
from business_logic import evaluate_security_rules
from analytical_layer import (
    get_kpi_metrics,
    get_security_activity_timeline,
    get_department_risk_summary,
    get_security_signal_breakdown,
    generate_security_insights
)

# ==========================================
# PAGE CONFIGURATION & STYLING
# ==========================================
st.set_page_config(
    page_title="SOC Command Center | Zero-Trust Telemetry",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Dark cybersecurity command center theme styling
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .metric-card {
        background: #1e222d;
        border-radius: 8px;
        padding: 15px;
        border-left: 4px solid #4CAF50;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .critical-card {
        border-left: 4px solid #ff4444 !important;
    }
    .high-card {
        border-left: 4px solid #ff8800 !important;
    }
    .insight-box {
        background-color: #1a2234;
        border-left: 4px solid #2196F3;
        padding: 12px;
        margin-bottom: 8px;
        border-radius: 4px;
        font-size: 0.95rem;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# CACHED DATA PIPELINE INITIALIZATION
# ==========================================
@st.cache_data(show_spinner=False)
def load_analytical_model():
    """
    Builds the star schema dimensions, facts, correlations, and risk scores.
    Executed once and cached for high dashboard performance.
    """
    dim_master = build_dim_identity_asset()
    fact_iam = build_fact_iam()
    fact_endpoint = build_fact_endpoint()
    fact_firewall = build_fact_firewall()

    # Cross-System Correlations
    session_corr = correlate_iam_firewall_sessions(fact_iam, fact_firewall)
    proximity_corr = correlate_iam_firewall_proximity(fact_iam, fact_firewall, tolerance_minutes=30)
    cross_summary = get_cross_system_summary(fact_iam, fact_endpoint, fact_firewall)

    # Risk Scoring
    user_risk = calculate_user_risk_profile(dim_master, fact_iam, fact_endpoint, fact_firewall, session_corr)
    host_risk = calculate_host_risk_profile(dim_master, fact_iam, fact_endpoint, fact_firewall)

    # Model diagnostics
    diagnostics = validate_data_model(dim_master, fact_iam, fact_endpoint, fact_firewall)

    # Business Rules
    rules = evaluate_security_rules(dim_master, fact_iam, fact_endpoint, fact_firewall, session_corr)

    return (
        dim_master, fact_iam, fact_endpoint, fact_firewall,
        session_corr, proximity_corr, cross_summary,
        user_risk, host_risk, diagnostics, rules
    )

with st.spinner("Initializing Zero-Trust Security Data Architecture..."):
    (
        dim_master, fact_iam, fact_endpoint, fact_firewall,
        session_corr, proximity_corr, cross_summary,
        user_risk, host_risk, diagnostics, rules
    ) = load_analytical_model()

# ==========================================
# SIDEBAR NAVIGATION & GLOBAL FILTERS
# ==========================================
st.sidebar.title("🛡️ SOC Operations")
st.sidebar.markdown("---")

app_view = st.sidebar.radio(
    "Navigation Console",
    [
        "1. 🏛️ Command Center Overview",
        "2. 👤 Identity & IAM Investigation",
        "3. 💻 Endpoint Alert Investigation",
        "4. 🌐 Network & Firewall Investigation",
        "5. 🔗 Cross-System Correlation Matrix"
    ]
)

st.sidebar.markdown("---")
st.sidebar.subheader("🎯 Global Scope Filters")

all_departments = sorted(dim_master['department'].dropna().unique())
selected_depts = st.sidebar.multiselect(
    "Department Scope",
    options=all_departments,
    default=all_departments
)

all_risk_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
selected_risk_levels = st.sidebar.multiselect(
    "Risk Level Filter",
    options=all_risk_levels,
    default=all_risk_levels
)

# Apply global cascading filters
filtered_master = dim_master[dim_master['department'].isin(selected_depts)]
valid_uids = set(filtered_master['user_id'])
valid_hosts = set(filtered_master['hostname_norm'].dropna())

filtered_user_risk = user_risk[
    user_risk['department'].isin(selected_depts) &
    user_risk['risk_level'].isin(selected_risk_levels)
]

filtered_host_risk = host_risk[
    host_risk['risk_level'].isin(selected_risk_levels)
]

# Calculate global KPIs
kpis = get_kpi_metrics(filtered_user_risk, fact_iam, fact_endpoint, fact_firewall, filtered_master)

st.sidebar.markdown("---")
st.sidebar.caption("Star-Schema Architecture: `DIM_IDENTITY_ASSET` (3,000) ↔ `FACT_IAM` (20,000) ↔ `FACT_ENDPOINT` (8,000) ↔ `FACT_FIREWALL` (30,000)")


# ==============================================================================
# VIEW 1: COMMAND CENTER OVERVIEW
# ==============================================================================
if app_view == "1. 🏛️ Command Center Overview":
    st.title("🛡️ Security Operations Command Center")
    st.markdown(
        "Unified cross-telemetry threat intelligence aggregating **Identity (IAM)**, "
        "**Endpoint (EDR)**, and **Perimeter (Firewall)** data into actionable risk metrics."
    )

    # --------------------------------------------------------
    # SECTION 1: SECURITY KPIS
    # --------------------------------------------------------
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Critical Risk Users", f"{kpis['critical_users']:,}", delta="Urgent" if kpis['critical_users'] > 0 else "Normal", delta_color="inverse")
    c2.metric("High Risk Users", f"{kpis['high_users']:,}", delta="Review" if kpis['high_users'] > 0 else "Normal", delta_color="inverse")
    c3.metric("Failed Logins", f"{kpis['failed_logins']:,}")
    c4.metric("Endpoint Alerts", f"{kpis['total_alerts']:,}")
    c5.metric("Firewall Denies", f"{kpis['firewall_denies']:,}")

    st.markdown("---")

    # --------------------------------------------------------
    # SECTION 2: SECURITY ACTIVITY TIMELINE
    # --------------------------------------------------------
    st.subheader("📈 Integrated Security Activity Trend")
    timeline_df = get_security_activity_timeline(fact_iam, fact_endpoint, fact_firewall, valid_uids, valid_hosts)
    
    if not timeline_df.empty:
        fig_timeline = px.line(
            timeline_df, x='date', y=['Failed Logins', 'Endpoint Alerts', 'Firewall Blocks'],
            color_discrete_map={'Failed Logins': '#FFA726', 'Endpoint Alerts': '#EF5350', 'Firewall Blocks': '#42A5F5'},
            labels={'value': 'Event Count', 'date': 'Timeline Date', 'variable': 'Security Vector'}
        )
        fig_timeline.update_layout(
            height=320,
            margin=dict(l=20, r=20, t=20, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            hovermode="x unified"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No security activity recorded for selected parameters.")

    st.markdown("---")

    # --------------------------------------------------------
    # SECTION 3 & 4: TOP AT-RISK USERS & HOSTS
    # --------------------------------------------------------
    col_u, col_h = st.columns(2)

    with col_u:
        st.subheader("🚨 Top At-Risk Identities (Actionable Hitlist)")
        user_table_cols = [
            'user_id', 'full_name', 'department', 'risk_score', 
            'risk_level', 'failed_logins', 'total_endpoint_alerts', 'main_reason'
        ]
        top_users_display = filtered_user_risk[user_table_cols].head(10).rename(columns={
            'user_id': 'User ID',
            'full_name': 'Employee Name',
            'department': 'Dept',
            'risk_score': 'Score',
            'risk_level': 'Level',
            'failed_logins': 'Fails',
            'total_endpoint_alerts': 'Alerts',
            'main_reason': 'Primary Explanations'
        })
        st.dataframe(top_users_display, use_container_width=True, hide_index=True)

    with col_h:
        st.subheader("🖥️ Top At-Risk Endpoints (Host Systems)")
        host_table_cols = [
            'hostname_norm', 'department', 'risk_score', 
            'risk_level', 'endpoint_alerts', 'firewall_denies', 'main_reason'
        ]
        top_hosts_display = filtered_host_risk[host_table_cols].head(10).rename(columns={
            'hostname_norm': 'Hostname',
            'department': 'Dept',
            'risk_score': 'Score',
            'risk_level': 'Level',
            'endpoint_alerts': 'EDR Alerts',
            'firewall_denies': 'FW Blocks',
            'main_reason': 'Primary Explanations'
        })
        st.dataframe(top_hosts_display, use_container_width=True, hide_index=True)

    st.markdown("---")

    # --------------------------------------------------------
    # SECTION 5 & 6: RISK BY DEPARTMENT & SIGNAL BREAKDOWN
    # --------------------------------------------------------
    col_d, col_s = st.columns(2)

    with col_d:
        st.subheader("🏢 High & Critical Identities by Department")
        dept_summary = get_department_risk_summary(filtered_user_risk)
        if not dept_summary.empty:
            fig_dept = px.bar(
                dept_summary, x='department', y='high_or_crit_users',
                color='avg_risk',
                color_continuous_scale='Reds',
                labels={'department': 'Department', 'high_or_crit_users': 'High/Critical Users', 'avg_risk': 'Avg Risk'}
            )
            fig_dept.update_layout(height=300, margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig_dept, use_container_width=True)

    with col_s:
        st.subheader("📊 Security Signal Volume Breakdown")
        total_correlations = len(session_corr) + len(proximity_corr)
        signal_df = get_security_signal_breakdown(kpis, total_correlations)
        fig_pie = px.pie(
            signal_df, values='Count', names='Source',
            color='Source',
            color_discrete_map={
                'IAM Failures': '#FFA726',
                'Endpoint Alerts': '#EF5350',
                'Firewall Blocks': '#42A5F5',
                'Correlated Events': '#AB47BC'
            },
            hole=0.45
        )
        fig_pie.update_layout(height=300, margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown("---")

    # --------------------------------------------------------
    # SECTION 7: AUTOMATED ANALYTICAL INSIGHTS
    # --------------------------------------------------------
    st.subheader("🧠 Security Operations Automated Insights")
    insights = generate_security_insights(filtered_user_risk, filtered_host_risk, dept_summary, total_correlations)
    for ins in insights:
        st.markdown(f"<div class='insight-box'>{ins}</div>", unsafe_allow_html=True)


# ==============================================================================
# VIEW 2: USER & IDENTITY INVESTIGATION
# ==============================================================================
elif app_view == "2. 👤 Identity & IAM Investigation":
    st.title("👤 Identity & Access Management (IAM) Investigation")
    st.markdown("Deep dive into credential attacks, brute-force attempts, and MFA security anomalies.")

    f_iam = fact_iam[fact_iam['user_id'].isin(valid_uids)].copy()
    failed_logins_all = f_iam[f_iam['event_category'].isin(['login_failed', 'mfa_failure'])].copy()

    ic1, ic2, ic3, ic4 = st.columns(4)
    ic1.metric("Total IAM Audit Events", f"{len(f_iam):,}")
    ic2.metric("Authentication Failures", f"{len(failed_logins_all):,}")
    ic3.metric("MFA Failures", f"{(f_iam['event_category'] == 'mfa_failure').sum():,}")
    ic4.metric("Avg IAM Telemetry Risk", f"{f_iam['risk_score'].mean():.1f}")

    st.markdown("---")
    r1_col1, r1_col2 = st.columns(2)

    with r1_col1:
        st.subheader("Failed Logins Trend by Department")
        if not failed_logins_all.empty and failed_logins_all['timestamp'].notna().any():
            failed_logins_all['date'] = failed_logins_all['timestamp'].dt.date
            dept_trend = failed_logins_all.groupby(['date', 'department']).size().reset_index(name='count')
            fig_iam_dept = px.line(dept_trend, x='date', y='count', color='department', markers=True)
            fig_iam_dept.update_layout(height=350)
            st.plotly_chart(fig_iam_dept, use_container_width=True)
        else:
            st.info("No failure timestamps available.")

    with r1_col2:
        st.subheader("Top 10 Users by Authentication Failures")
        top_u_fails = failed_logins_all.groupby('user_id').size().reset_index(name='failed_attempts')
        top_u_fails = top_u_fails.sort_values(by='failed_attempts', ascending=False).head(10)
        top_u_fails = top_u_fails.merge(dim_master[['user_id', 'full_name', 'department']], on='user_id', how='left')
        fig_fails = px.bar(top_u_fails, x='user_id', y='failed_attempts', color='department', hover_data=['full_name'])
        fig_fails.update_layout(height=350)
        st.plotly_chart(fig_fails, use_container_width=True)

    st.markdown("---")
    st.subheader("Failure Reasons Breakdown & Attack Signatures")
    fc1, fc2 = st.columns(2)
    with fc1:
        reasons_dist = f_iam['failure_reason'].value_counts().reset_index()
        reasons_dist.columns = ['Failure Reason', 'Count']
        fig_reasons = px.bar(reasons_dist.head(8), x='Count', y='Failure Reason', orientation='h', color='Count', color_continuous_scale='Oranges')
        fig_reasons.update_layout(height=300)
        st.plotly_chart(fig_reasons, use_container_width=True)

    with fc2:
        st.markdown("**Rule 2 Detections: Repeated MFA Failures (>= 2)**")
        rule2_table = rules['rule2_repeated_mfa_failures']
        st.dataframe(rule2_table.head(15), use_container_width=True, hide_index=True)


# ==============================================================================
# VIEW 3: ENDPOINT INVESTIGATION
# ==============================================================================
elif app_view == "3. 💻 Endpoint Alert Investigation":
    st.title("💻 Endpoint Detection & Response (EDR) Alerts")
    st.markdown("Investigate malware classifications, high-criticality host devices, and malicious execution.")

    f_ep = fact_endpoint[fact_endpoint['user_id'].isin(valid_uids)].copy()

    ec1, ec2, ec3, ec4 = st.columns(4)
    ec1.metric("Total Endpoint Alerts", f"{len(f_ep):,}")
    ec2.metric("Critical Alerts", f"{(f_ep['severity'] == 'CRITICAL').sum():,}")
    ec3.metric("High Severity Alerts", f"{(f_ep['severity'] == 'HIGH').sum():,}")
    ec4.metric("Unique Target Hosts", f"{f_ep['hostname_norm'].nunique():,}")

    st.markdown("---")
    ep_c1, ep_c2 = st.columns(2)

    with ep_c1:
        st.subheader("Endpoint Alert Types by Severity")
        alert_counts = f_ep.groupby(['alert_name', 'severity']).size().reset_index(name='count')
        fig_alerts = px.bar(
            alert_counts, x='count', y='alert_name', color='severity', orientation='h',
            color_discrete_map={'CRITICAL': '#b71c1c', 'HIGH': '#e53935', 'MEDIUM': '#fb8c00', 'LOW': '#fdd835', 'UNKNOWN': '#9e9e9e'}
        )
        fig_alerts.update_layout(height=400, yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_alerts, use_container_width=True)

    with ep_c2:
        st.subheader("Severity Distribution Across Hostnames")
        sev_dist = f_ep['severity'].value_counts().reset_index()
        sev_dist.columns = ['Severity', 'Count']
        fig_sev_pie = px.pie(
            sev_dist, names='Severity', values='Count',
            color='Severity',
            color_discrete_map={'CRITICAL': '#b71c1c', 'HIGH': '#e53935', 'MEDIUM': '#fb8c00', 'LOW': '#fdd835'}
        )
        fig_sev_pie.update_layout(height=400)
        st.plotly_chart(fig_sev_pie, use_container_width=True)

    st.markdown("---")
    st.subheader("Critical Endpoint Detections Table")
    crit_table = f_ep[f_ep['severity'].isin(['CRITICAL', 'HIGH'])][[
        'alert_id', 'detected_timestamp', 'hostname_norm', 'user_id', 
        'alert_name', 'severity', 'process_name', 'status'
    ]].sort_values(by='detected_timestamp', ascending=False)
    st.dataframe(crit_table.head(25), use_container_width=True, hide_index=True)


# ==============================================================================
# VIEW 4: NETWORK / FIREWALL INVESTIGATION
# ==============================================================================
elif app_view == "4. 🌐 Network & Firewall Investigation":
    st.title("🌐 Network Perimeter & Firewall Telemetry")
    st.markdown("Global origin mapping, perimeter block patterns, and protocol telemetry analysis.")

    f_fw = fact_firewall[fact_firewall['hostname_norm'].isin(valid_hosts)].copy()

    nc1, nc2, nc3, nc4 = st.columns(4)
    nc1.metric("Total Firewall Logs", f"{len(f_fw):,}")
    nc2.metric("Perimeter Deny Actions", f"{(f_fw['action'] == 'deny').sum():,}")
    nc3.metric("Allow Actions", f"{(f_fw['action'] == 'allow').sum():,}")
    nc4.metric("Threat Flags Raised", f"{int(f_fw['threat_flag'].sum()):,}")

    st.markdown("---")
    st.subheader("🌍 Global Threat Origins (Blocked Connections)")
    fw_geo = f_fw[f_fw['action'] == 'deny'].groupby('geo_country').size().reset_index(name='blocks')
    fig_map = px.choropleth(
        fw_geo, locations="geo_country", locationmode="country names", 
        color="blocks", hover_name="geo_country", 
        color_continuous_scale="Reds"
    )
    fig_map.update_layout(
        height=380,
        geo=dict(showframe=False, showcoastlines=True, projection_type='equirectangular'),
        margin=dict(l=10, r=10, t=10, b=10)
    )
    st.plotly_chart(fig_map, use_container_width=True)

    st.markdown("---")
    fw_col1, fw_col2 = st.columns(2)

    with fw_col1:
        st.subheader("Firewall Deny Trend by Protocol")
        fw_deny = f_fw[f_fw['action'] == 'deny'].copy()
        if not fw_deny.empty and fw_deny['timestamp'].notna().any():
            fw_deny['date'] = fw_deny['timestamp'].dt.date
            fw_trend = fw_deny.groupby(['date', 'protocol']).size().reset_index(name='count')
            fig_fw_proto = px.area(fw_trend, x='date', y='count', color='protocol')
            fig_fw_proto.update_layout(height=320)
            st.plotly_chart(fig_fw_proto, use_container_width=True)
        else:
            st.info("No firewall deny timestamps available.")

    with fw_col2:
        st.subheader("Top Attacked / Blocked Destination Ports")
        port_counts = f_fw[f_fw['action'] == 'deny']['dst_port'].value_counts().reset_index().head(10)
        port_counts.columns = ['Destination Port', 'Blocks']
        port_counts['Destination Port'] = port_counts['Destination Port'].astype(str)
        fig_ports = px.bar(port_counts, x='Destination Port', y='Blocks', color='Blocks', color_continuous_scale='Blues')
        fig_ports.update_layout(height=320)
        st.plotly_chart(fig_ports, use_container_width=True)


# ==============================================================================
# VIEW 5: CROSS-SYSTEM CORRELATION MATRIX
# ==============================================================================
elif app_view == "5. 🔗 Cross-System Correlation Matrix":
    st.title("🔗 Cross-System Correlation & Entity Linkage")
    st.markdown(
        "Demonstrates the power of the analytical data model by correlating security telemetry "
        "across **Identity Master**, **IAM Sessions**, **EDR Alerts**, and **Perimeter Firewalls**."
    )

    # Cross system metric cards
    cc1, cc2, cc3, cc4 = st.columns(4)
    cc1.metric("Tri-System Hosts", f"{cross_summary['total_tri_system_hosts']:,}", help="Hosts appearing across IAM, EDR, and Firewall")
    cc2.metric("IAM + Endpoint Users", f"{cross_summary['total_iam_endpoint_users']:,}", help="Users with both IAM activity and EDR alerts")
    cc3.metric("Multi-Vector Threat Users", f"{cross_summary['high_threat_insider_users']:,}", help="Users with failed logins + Critical/High alerts")
    cc4.metric("Session Matches", f"{len(session_corr):,}", help="Exact IAM ↔ Firewall session_id joins")

    st.markdown("---")

    tab_session, tab_prox, tab_diag = st.tabs([
        "🔑 IAM ↔ Firewall Session Correlations",
        "⏱️ Host & Temporal Proximity (30m)",
        "📊 Join Validation Diagnostics"
    ])

    with tab_session:
        st.subheader("Correlated Events via Shared `session_id`")
        st.markdown(
            "Identifies exact instances where an IAM authentication session is matched "
            "with perimeter network connections recorded in the firewall logs."
        )
        if not session_corr.empty:
            display_sess = session_corr[[
                'session_id_norm', 'user_id', 'hostname_norm_iam', 'timestamp_iam', 
                'event_category', 'hostname_norm_fw', 'timestamp_fw', 'action', 'dst_ip'
            ]].head(50).rename(columns={
                'session_id_norm': 'Session ID',
                'user_id': 'User ID',
                'hostname_norm_iam': 'IAM Host',
                'timestamp_iam': 'IAM Timestamp',
                'event_category': 'IAM Event',
                'hostname_norm_fw': 'FW Host',
                'timestamp_fw': 'FW Timestamp',
                'action': 'FW Action',
                'dst_ip': 'Dst IP'
            })
            st.dataframe(display_sess, use_container_width=True, hide_index=True)

            csv_sess = display_sess.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Download Correlated Sessions CSV",
                data=csv_sess,
                file_name="iam_firewall_correlated_sessions.csv",
                mime="text/csv"
            )
        else:
            st.info("No session matches found.")

    with tab_prox:
        st.subheader("Correlated Events via Same Host & Temporal Proximity (±30 Min)")
        st.markdown(
            "Calculates high-probability attack chains where an IAM authentication attempt "
            "and firewall connection occur on the exact same host within a 30-minute operational window."
        )
        if not proximity_corr.empty:
            disp_prox = proximity_corr[[
                'hostname_norm', 'user_id', 'timestamp', 'event_category', 
                'log_id', 'action', 'protocol', 'dst_ip'
            ]].head(50).rename(columns={
                'hostname_norm': 'Hostname',
                'user_id': 'User ID',
                'timestamp': 'Timestamp',
                'event_category': 'IAM Action',
                'log_id': 'FW Log ID',
                'action': 'FW Action',
                'protocol': 'Protocol',
                'dst_ip': 'Dst IP'
            })
            st.dataframe(disp_prox, use_container_width=True, hide_index=True)

            csv_prox = disp_prox.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Download Proximity Correlations CSV",
                data=csv_prox,
                file_name="iam_firewall_host_proximity_correlations.csv",
                mime="text/csv"
            )
        else:
            st.info("No host proximity correlations within window.")

    with tab_diag:
        st.subheader("Analytical Data Model Join Quality Diagnostics")
        st.markdown("Verifies that all joins maintain high match rates and zero unexpected row multiplication.")

        d_col1, d_col2, d_col3 = st.columns(3)

        with d_col1:
            st.markdown("### IAM ↔ Identity Master")
            iam_d = diagnostics['iam_to_master']
            st.write(f"- **Source Rows**: `{iam_d['source_rows']:,}`")
            st.write(f"- **Matched Rows**: `{iam_d['matched_rows']:,}`")
            st.write(f"- **Unmatched Rows**: `{iam_d['unmatched_rows']:,}`")
            st.write(f"- **Match Rate**: `{iam_d['match_pct']}%`")
            st.write(f"- **Master Duplicate Keys**: `{iam_d['master_key_duplicates']}`")

        with d_col2:
            st.markdown("### Endpoint ↔ Identity Master")
            ep_d = diagnostics['endpoint_to_master']
            st.write(f"- **Source Rows**: `{ep_d['source_rows']:,}`")
            st.write(f"- **Matched on User**: `{ep_d['matched_user_rows']:,}` (`{ep_d['match_user_pct']}%`)")
            st.write(f"- **Matched on Host**: `{ep_d['matched_host_rows']:,}` (`{ep_d['match_host_pct']}%`)")
            st.write(f"- **Null Host Keys in Source**: `{ep_d['null_host_keys']}`")

        with d_col3:
            st.markdown("### Firewall ↔ Identity Master")
            fw_d = diagnostics['firewall_to_master']
            st.write(f"- **Source Rows**: `{fw_d['source_rows']:,}`")
            st.write(f"- **Matched Rows**: `{fw_d['matched_rows']:,}`")
            st.write(f"- **Match Rate**: `{fw_d['match_pct']}%`")
            st.write(f"- **Null Host Keys in Source**: `{fw_d['null_keys']}`")

st.sidebar.caption("SOC Command Center v2.0 • Data Architecture Upgrade")
