import pandas as pd
TRANSACTION_THRESHOLD = 3
TIME_WINDOW_MINUTES = 10
def calculate_risk(transactions, unique_ips):
    score = (transactions * 2) + (unique_ips * 5)
    if score >= 21:
        level = "HIGH"
    elif score >= 11:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level
def analyze_transactions(df):
    suspicious = []
    required_columns = [
        "card_number",
        "transaction_time",
        "ip_address"
    ]
    for col in required_columns:
        if col not in df.columns:
            return {"error": f"Missing column {col}"}
    df["transaction_time"] = pd.to_datetime(df["transaction_time"])
    grouped = df.groupby("card_number")
    for card, group in grouped:
        group = group.sort_values("transaction_time")
        if len(group) >= TRANSACTION_THRESHOLD:
            time_span = (
                group["transaction_time"].max()
                - group["transaction_time"].min()
            ).total_seconds() / 60
            unique_ips = group["ip_address"].nunique()
            if unique_ips > 1 and time_span <= TIME_WINDOW_MINUTES:
                risk_score, risk_level = calculate_risk(
                    len(group), unique_ips
                )
                suspicious.append({
                    "card_number": card,
                    "transactions": int(len(group)),
                    "unique_ips": int(unique_ips),
                    "time_span_minutes": round(time_span, 2),
                    "risk_score": int(risk_score),
                    "risk_level": risk_level,
                    "reason": "Multiple IP addresses used within short time window"
                })
    return suspicious
