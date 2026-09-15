import streamlit as st
import pandas as pd
import plotly.express as px
import os
import json
from groq import Groq
from dotenv import load_dotenv

# --- LOAD ENVIRONMENT VARIABLES ---
load_dotenv()

# --- PAGE CONFIG ---
st.set_page_config(page_title="AgentIQ: Groq-Powered Graph AI", layout="centered", page_icon="🤖")

# Model is configurable via env var so future Groq deprecations don't require a code change.
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# --- LOAD DATA ---
@st.cache_data
def load_data():
    master = pd.read_csv('cleaned_identity_asset_master.csv')
    fw = pd.read_csv('cleaned_firewall_logs.csv')
    iam = pd.read_csv('cleaned_iam_audit_trail.csv')
    alerts = pd.read_csv('cleaned_endpoint_alerts.csv')

    iam['timestamp'] = pd.to_datetime(iam['timestamp'])
    fw['timestamp'] = pd.to_datetime(fw['timestamp'])
    return master, fw, iam, alerts

try:
    master, fw, iam, alerts = load_data()
except FileNotFoundError as e:
    st.error(f"⚠️ Could not find a required data file: {e}. "
             f"Make sure the CSVs are in the same directory as this script.")
    st.stop()
except Exception as e:
    st.error(f"⚠️ Failed to load data: {e}")
    st.stop()

# --- INITIALIZE GROQ CLIENT ---
api_key = os.getenv("GROQ_API_KEY")
api_configured = False
client = None
if api_key:
    try:
        client = Groq(api_key=api_key)
        api_configured = True
    except Exception as e:
        st.warning(f"⚠️ Found a GROQ_API_KEY but failed to initialize the Groq client: {e}")

st.title("🤖 AgentIQ: Groq Text-to-Chart AI")
st.markdown(f"*Ask questions in natural language. Powered by `{GROQ_MODEL}` via Groq.*")

if not api_configured:
    st.warning("⚠️ GROQ_API_KEY not found. Please create a `.env` file and add your key.")
    st.info("Example `.env` file contents:\n\n`GROQ_API_KEY=gsk_your_api_key_here`")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "Hello! I am your Cyber-Command AI powered by Groq. Ask me questions like: \n- *'Show the trend of failed login attempts by department'* \n- *'Show endpoint alerts by severity'*"}
    ]

# Display chat history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if "chart" in msg and msg["chart"] is not None:
            st.plotly_chart(msg["chart"], use_container_width=True)

# Chat input
if prompt := st.chat_input("Ask a business question..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    if api_configured:
        system_prompt = """
        You are a cybersecurity AI agent. The user will ask a question about their data.
        You must classify their request into one of the following exact 'intent' strings:
        - 'failed_logins_trend' (if they ask about trend/time of failed logins by department)
        - 'alerts_by_severity' (if they ask about endpoint alerts by severity)
        - 'top_failed_users' (if they ask about which users have the most failed logins)
        - 'firewall_deny_trend' (if they ask about firewall deny/blocked actions)
        - 'help' (if they are asking what they can ask you, what questions are available, or are confused about how to use you — NOT a data question itself)
        - 'unknown' (if it doesn't match any of the above)

        You must return a raw JSON object with exactly two keys: 'intent' and 'summary'.
        The 'summary' should be a short 1-2 sentence response to the user's query that will accompany the chart.
        DO NOT wrap the JSON in markdown blocks (```json). Just return the raw JSON braces.
        """

        response_str = ""
        intent = "error"
        response_text = "Something went wrong before a response could be generated."

        with st.spinner("🧠 Groq is analyzing your request..."):
            try:
                completion = client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    response_format={"type": "json_object"}
                )

                response_str = completion.choices[0].message.content.strip()

                # Some models ignore the "no markdown" instruction, so strip fences defensively.
                cleaned = response_str
                if cleaned.startswith("```"):
                    cleaned = cleaned.strip("`")
                    if cleaned.lower().startswith("json"):
                        cleaned = cleaned[4:].strip()

                ai_response = json.loads(cleaned)

                intent = ai_response.get("intent", "unknown")
                response_text = ai_response.get("summary", "Here is what I found.")

            except json.JSONDecodeError as e:
                intent = "error"
                response_text = f"Groq returned a response I couldn't parse as JSON: {e}. Raw response: {response_str or 'None'}"
            except Exception as e:
                intent = "error"
                response_text = f"An error occurred calling Groq: {e}"

        chart = None

        # --- DYNAMIC CHART GENERATION BASED ON GROQ'S INTENT ---
        if intent == "failed_logins_trend":
            failed_logins = iam[iam['event_category'] == 'login_failed'].copy()
            if failed_logins.empty:
                response_text = "I looked, but there are no failed login events in the data."
            else:
                failed_logins['date'] = failed_logins['timestamp'].dt.date
                trend_data = failed_logins.groupby(['date', 'department']).size().reset_index(name='count')
                chart = px.line(trend_data, x='date', y='count', color='department',
                                title="Trend of Failed Logins by Department")

        elif intent == "alerts_by_severity":
            if alerts.empty or 'severity' not in alerts.columns:
                response_text = "I couldn't find any endpoint alert severity data."
            else:
                alert_counts = alerts['severity'].value_counts().reset_index()
                alert_counts.columns = ['severity', 'count']
                chart = px.bar(alert_counts, x='severity', y='count', color='severity',
                               title="Endpoint Alerts by Severity",
                               color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'})

        elif intent == "top_failed_users":
            failed_logins = iam[iam['event_category'] == 'login_failed']
            if failed_logins.empty:
                response_text = "There are no failed login events to rank users by."
            else:
                top_users = failed_logins['user_id'].value_counts().head(10).reset_index()
                top_users.columns = ['user_id', 'failed_attempts']
                chart = px.bar(top_users, x='user_id', y='failed_attempts',
                               title="Top 10 Users with Most Failed Logins")

        elif intent == "firewall_deny_trend":
            fw_deny = fw[fw['action'] == 'deny'].copy()
            if fw_deny.empty:
                response_text = "I didn't find any firewall deny/blocked actions in the data."
            else:
                fw_deny['date'] = fw_deny['timestamp'].dt.date
                fw_trend = fw_deny.groupby(['date', 'protocol']).size().reset_index(name='count')
                chart = px.area(fw_trend, x='date', y='count', color='protocol',
                                 title="Firewall Deny Actions by Protocol Over Time")

        elif intent == "help":
            response_text = (
                "Here are some things you can ask me:\n\n"
                "- *Show the trend of failed login attempts by department*\n"
                "- *Show endpoint alerts by severity*\n"
                "- *Which users have the most failed logins?*\n"
                "- *Show firewall deny actions over time*"
            )
            chart = None

        elif intent == "unknown":
            response_text = "I'm sorry, I couldn't map your question to a specific security chart. Please try asking a full question like 'Show the trend of failed login attempts by department'."
            chart = None

        elif intent == "error":
            chart = None

        st.session_state.messages.append({"role": "assistant", "content": response_text, "chart": chart})
        with st.chat_message("assistant"):
            st.markdown(response_text)
            if chart is not None:
                st.plotly_chart(chart, use_container_width=True)
    else:
        with st.chat_message("assistant"):
            st.markdown("⚠️ Please create a `.env` file and set your GROQ_API_KEY first!")