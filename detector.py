import pandas as pd
TRANSACTION_THRESHOLD = 3
def analyze_transactions(df):
    suspicious = []
    required_columns = ["card_number", "transaction_time", "ip_address"]
    for col in required_columns:
        if col not in df.columns:
            return {"error": f"Missing column {col}"}
    df["transaction_time"] = pd.to_datetime(df["transaction_time"])
    grouped = df.groupby("card_number")
    for card, group in grouped:
        group = group.sort_values("transaction_time")
        if len(group) >= TRANSACTION_THRESHOLD:
            unique_ips = group["ip_address"].nunique()
            if unique_ips > 1:
                suspicious.append({
                    "card_number": card,
                    "transactions": len(group),
                    "unique_ips": unique_ips
                })
    return suspicious
