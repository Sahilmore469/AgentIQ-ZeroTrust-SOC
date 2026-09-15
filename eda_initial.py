import pandas as pd

def main():
    print("================ IDENTITY ASSET MASTER ================")
    df_master = pd.read_csv('track2_identity_asset_master.csv')
    print(f"Shape: {df_master.shape}")
    print(df_master.head(3))
    print("\nSample User IDs:", df_master['user_id'].dropna().head(10).tolist())
    if 'department' in df_master.columns:
        print("\nUnique Departments (first 15):", df_master['department'].dropna().unique()[:15])

    print("\n================ FIREWALL LOGS ================")
    df_fw = pd.read_csv('track2_firewall_logs.csv', nrows=1000)
    print(f"Shape (first 1000 rows): {df_fw.shape}")
    print(df_fw.head(3))

    print("\n================ IAM AUDIT TRAIL ================")
    try:
        df_iam = pd.read_json('track2_iam_audit_trail.json')
        print(f"Shape: {df_iam.shape}")
        print(df_iam.head(3))
    except Exception as e:
        print(f"Error reading JSON: {e}")

    print("\n================ ENDPOINT ALERTS ================")
    try:
        df_alerts = pd.read_excel('track2_endpoint_alerts.xlsx')
        print(f"Shape: {df_alerts.shape}")
        print(df_alerts.head(3))
    except Exception as e:
        print(f"Error reading Excel: {e}")

if __name__ == "__main__":
    main()
