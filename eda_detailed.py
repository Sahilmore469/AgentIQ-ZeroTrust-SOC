import pandas as pd
import json

def main():
    df_master = pd.read_csv('track2_identity_asset_master.csv')
    df_fw = pd.read_csv('track2_firewall_logs.csv', nrows=2000)
    df_iam = pd.read_json('track2_iam_audit_trail.json')
    df_alerts = pd.read_excel('track2_endpoint_alerts.xlsx')

    print("--- Master Columns ---")
    print(df_master.columns.tolist())
    
    print("--- FW Columns ---")
    print(df_fw.columns.tolist())
    print("\nFW Actions:", df_fw['action'].dropna().unique() if 'action' in df_fw.columns else 'No action col')
    
    print("--- IAM Columns ---")
    print(df_iam.columns.tolist())
    print("\nIAM Event Types:", df_iam['event_type'].dropna().unique() if 'event_type' in df_iam.columns else 'No event_type')
    
    print("--- Alerts Columns ---")
    print(df_alerts.columns.tolist())
    print("\nAlert Severities:", df_alerts['severity'].dropna().unique() if 'severity' in df_alerts.columns else 'No severity')

if __name__ == "__main__":
    main()
