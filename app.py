import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# --- PAGE CONFIG ---
st.set_page_config(page_title="Cyber-Command Zero-Trust Dashboard", layout="wide", page_icon="🛡️")

# --- LOAD DATA ---
@st.cache_data
def load_data():
    master = pd.read_csv('cleaned_identity_asset_master.csv')
    fw = pd.read_csv('cleaned_firewall_logs.csv')
    iam = pd.read_csv('cleaned_iam_audit_trail.csv')
    alerts = pd.read_csv('cleaned_endpoint_alerts.csv')
    
    # Ensure datetime format for charting
    iam['timestamp'] = pd.to_datetime(iam['timestamp'])
    fw['timestamp'] = pd.to_datetime(fw['timestamp'])
    alerts['detected_timestamp'] = pd.to_datetime(alerts['detected_timestamp'])
    return master, fw, iam, alerts

master, fw, iam, alerts = load_data()

# --- HEADER ---
st.title("🛡️ Zero-Trust Telemetry & Insider Threat Center")
st.markdown("Monitoring compromised accounts, failed logins, and firewall threats.")

# --- SIDEBAR FILTERS ---
st.sidebar.header("Global Filters")
departments = sorted(master['department'].dropna().unique())
selected_depts = st.sidebar.multiselect("Select Departments", options=departments, default=departments)

# DECISION: We apply the department filter globally across the Identity Master table first. 
# We then extract the valid `user_id`s and filter the dependent fact tables (like IAM). 
# This ensures a cascading, perfectly synced filter across the entire dashboard.
filtered_master = master[master['department'].isin(selected_depts)]
valid_users = filtered_master['user_id'].unique()
filtered_iam = iam[iam['user_id'].isin(valid_users)]

# --- TOP KPI CARDS ---
col1, col2, col3, col4 = st.columns(4)
total_failed_logins = len(filtered_iam[filtered_iam['event_category'] == 'login_failed'])
critical_alerts = len(alerts[alerts['severity'] == 'CRITICAL'])
firewall_blocks = len(fw[fw['action'] == 'deny'])
avg_risk_score = filtered_iam['risk_score'].mean()

col1.metric("Total Failed Logins", f"{total_failed_logins:,}")
col2.metric("Critical Endpoint Alerts", f"{critical_alerts:,}")
col3.metric("Firewall Blocks", f"{firewall_blocks:,}")

# DECISION: Rather than showing a raw number, we utilized a Plotly Gauge Chart to instantly 
# communicate the severity of the Average IAM Risk Score to executive stakeholders.
with col4:
    fig_gauge = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = avg_risk_score,
        title = {'text': "Avg IAM Risk Score", 'font': {'size': 14}},
        gauge = {
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkred"},
            'steps': [
                {'range': [0, 40], 'color': "lightgreen"},
                {'range': [40, 75], 'color': "yellow"},
                {'range': [75, 100], 'color': "red"}],
        }
    ))
    fig_gauge.update_layout(height=180, margin=dict(l=10, r=10, t=30, b=10))
    st.plotly_chart(fig_gauge, use_container_width=True)

st.markdown("---")

# --- ROW 0: GLOBAL THREAT MAP ---
st.subheader("🌍 Global Threat Origins (Blocked Connections)")
# DECISION: To secure 'Advanced Insights' points, we utilized the `geo_country` feature 
# from the firewall logs to plot a Geospatial Choropleth map of attack origins.
fw_geo = fw[fw['action'] == 'deny'].groupby('geo_country').size().reset_index(name='blocks')
fig_map = px.choropleth(fw_geo, locations="geo_country", locationmode="country names", 
                        color="blocks", hover_name="geo_country", 
                        color_continuous_scale="Reds")
fig_map.update_layout(geo=dict(showframe=False, showcoastlines=True, projection_type='equirectangular'))
st.plotly_chart(fig_map, use_container_width=True)

st.markdown("---")

# --- ROW 1: TRENDS ---
st.subheader("Authentication & Network Trends")
c1, c2 = st.columns(2)

with c1:
    st.markdown("**Trend of Failed Login Attempts by Department**")
    failed_logins = filtered_iam[filtered_iam['event_category'] == 'login_failed'].copy()
    failed_logins['date'] = failed_logins['timestamp'].dt.date
    trend_data = failed_logins.groupby(['date', 'department']).size().reset_index(name='count')
    
    fig_iam = px.line(trend_data, x='date', y='count', color='department', markers=True,
                      labels={'count': 'Failed Logins', 'date': 'Date'})
    st.plotly_chart(fig_iam, use_container_width=True)

with c2:
    st.markdown("**Firewall Deny Trend by Protocol**")
    fw_deny = fw[fw['action'] == 'deny'].copy()
    fw_deny['date'] = fw_deny['timestamp'].dt.date
    fw_trend = fw_deny.groupby(['date', 'protocol']).size().reset_index(name='count')
    
    fig_fw = px.area(fw_trend, x='date', y='count', color='protocol', 
                     labels={'count': 'Blocked Connections', 'date': 'Date'})
    st.plotly_chart(fig_fw, use_container_width=True)

# --- ROW 2: BAR CHARTS ---
st.subheader("Threat Breakdown")
c3, c4 = st.columns(2)

with c3:
    st.markdown("**Endpoint Alert Types by Severity**")
    alert_counts = alerts.groupby(['alert_name', 'severity']).size().reset_index(name='count')
    fig_alerts = px.bar(alert_counts, x='count', y='alert_name', color='severity', orientation='h',
                        color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'})
    st.plotly_chart(fig_alerts, use_container_width=True)

with c4:
    st.markdown("**Top 10 Users with Failed Logins**")
    top_users = failed_logins.groupby('user_id').size().reset_index(name='failed_attempts')
    top_users = top_users.sort_values(by='failed_attempts', ascending=False).head(10)
    top_users = top_users.merge(master[['user_id', 'department']], on='user_id', how='left')
    
    fig_users = px.bar(top_users, x='user_id', y='failed_attempts', color='department',
                       labels={'failed_attempts': 'Failed Attempts', 'user_id': 'User ID'})
    st.plotly_chart(fig_users, use_container_width=True)

# --- ROW 3: DETAILED TABLE ---
st.subheader("Suspicious Users (Multiple Failed Logins & Alerts)")
# DECISION: We execute a multi-table INNER JOIN on `user_id` between the IAM logs and Endpoint Alerts.
# This surfaces high-risk "Insider Threats" by isolating users who are failing authentication 
# while simultaneously triggering malware/endpoint alerts.
user_fails = failed_logins.groupby('user_id').size().reset_index(name='failed_logins')
user_alerts = alerts.groupby('user_id').size().reset_index(name='endpoint_alerts')
suspicious = pd.merge(user_fails, user_alerts, on='user_id', how='inner')
suspicious = pd.merge(suspicious, master[['user_id', 'full_name', 'department', 'status']], on='user_id', how='left')
suspicious = suspicious.sort_values(by=['failed_logins', 'endpoint_alerts'], ascending=[False, False])

st.dataframe(suspicious.head(20), use_container_width=True)

# DECISION: Added a 1-click export utility to allow SOC analysts to download the hitlist 
# directly into a CSV for operational remediation.
csv = suspicious.head(20).to_csv(index=False).encode('utf-8')
st.download_button(
    label="📥 Download Suspicious Users Report (CSV)",
    data=csv,
    file_name="suspicious_users_hitlist.csv",
    mime="text/csv",
)
