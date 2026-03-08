import pandas as pd
import networkx as nx
import requests
from sklearn.ensemble import IsolationForest
TRANSACTION_THRESHOLD = 3
TIME_WINDOW_MINUTES = 10
COLUMN_ALIASES = {
    "card_number":[
        "card_number","card","card_no","credit_card","cc","cardnum"
    ],
    "transaction_time":[
        "transaction_time","time","timestamp","date","datetime"
    ],
    "ip_address":[
        "ip_address","ip","ipaddr","ip_addr"
    ]
}
def normalize_columns(df):
    mapping = {}
    for standard, aliases in COLUMN_ALIASES.items():
        for col in df.columns:
            if col.lower() in aliases:
                mapping[col] = standard
    df = df.rename(columns=mapping)
    return df
def get_country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()
        return data.get("country","Unknown")
    except:
        return "Unknown"
def build_fraud_graph(df):
    G = nx.Graph()
    for _, row in df.iterrows():
        card = str(row["card_number"])
        ip = str(row["ip_address"])
        G.add_node(card, type="card")
        G.add_node(ip, type="ip")
        G.add_edge(card, ip)
    return G
def run_anomaly_detection(df):
    features = df.groupby("card_number").agg({
        "ip_address":"nunique",
        "transaction_time":"count"
    }).rename(columns={
        "ip_address":"unique_ips",
        "transaction_time":"transactions"
    })
    model = IsolationForest(contamination=0.05, random_state=42)
    features["anomaly"] = model.fit_predict(features)
    anomalies = features[features["anomaly"] == -1]
    return anomalies.index.tolist()
def calculate_risk(signals):
    score = 0
    score += signals["transactions"] * 2
    score += signals["unique_ips"] * 4
    if signals["velocity_flag"]:
        score += 10
    if signals["ip_reputation_flag"]:
        score += 8
    if signals["network_flag"]:
        score += 12
    if signals["behavioral_anomaly"]:
        score += 6
    if signals["geo_anomaly"]:
        score += 10
    if score >= 35:
        level = "CRITICAL"
    elif score >= 25:
        level = "HIGH"
    elif score >= 12:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level
def analyze_transactions(df):
    df = normalize_columns(df)
    required_columns = [
        "card_number",
        "transaction_time",
        "ip_address"
    ]
    missing = [c for c in required_columns if c not in df.columns]
    if missing:
        return {
            "error": f"Missing required columns: {missing}",
            "available_columns": list(df.columns)
        }
    df["transaction_time"] = pd.to_datetime(df["transaction_time"])
    grouped = df.groupby("card_number")
    ip_usage = df.groupby("ip_address")["card_number"].nunique()
    avg_transactions = df.groupby("card_number").size().mean()
    anomaly_cards = run_anomaly_detection(df)
    graph = build_fraud_graph(df)
    suspicious = []
    for card, group in grouped:
        group = group.sort_values("transaction_time")
        transactions = len(group)
        unique_ips = group["ip_address"].nunique()
        time_span = (
            group["transaction_time"].max()
            - group["transaction_time"].min()
        ).total_seconds() / 60
        velocity_flag = False
        ip_reputation_flag = False
        network_flag = False
        behavioral_anomaly = False
        geo_anomaly = False
        fraud_patterns = []
        if transactions >= TRANSACTION_THRESHOLD and time_span <= TIME_WINDOW_MINUTES and unique_ips > 1:
            velocity_flag = True
            fraud_patterns.append("Velocity Fraud")
        for ip in group["ip_address"]:
            if ip_usage[ip] > 5:
                ip_reputation_flag = True
                fraud_patterns.append("Suspicious IP Reputation")
            if ip_usage[ip] > 3:
                network_flag = True
                fraud_patterns.append("Fraud Ring Network")
        if card in anomaly_cards:
            behavioral_anomaly = True
            fraud_patterns.append("IsolationForest Anomaly")
        countries = set()
        for ip in group["ip_address"]:
            countries.add(get_country(ip))
        if len(countries) > 1 and time_span < 30:
            geo_anomaly = True
            fraud_patterns.append("Geo-location anomaly")
        signals = {
            "transactions":transactions,
            "unique_ips":unique_ips,
            "velocity_flag":velocity_flag,
            "ip_reputation_flag":ip_reputation_flag,
            "network_flag":network_flag,
            "behavioral_anomaly":behavioral_anomaly,
            "geo_anomaly":geo_anomaly
        }
        risk_score, risk_level = calculate_risk(signals)
        if risk_level in ["MEDIUM","HIGH","CRITICAL"]:
            suspicious.append({
                "card_number": card,
                "transactions": int(transactions),
                "unique_ips": int(unique_ips),
                "time_span_minutes": round(time_span,2),
                "risk_score": int(risk_score),
                "risk_level": risk_level,
                "fraud_patterns": list(set(fraud_patterns))
            })
    graph_nodes = [{"id":n, "type":graph.nodes[n]["type"]} for n in graph.nodes]
    graph_edges = [{"source":u,"target":v} for u,v in graph.edges]
    return {
        "suspicious_cards": suspicious,
        "fraud_network":{
            "nodes":graph_nodes,
            "edges":graph_edges
        }

    }
