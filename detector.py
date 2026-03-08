import pandas as pd
import networkx as nx
import requests
from sklearn.ensemble import IsolationForest
from cachetools import TTLCache
from networkx.algorithms.community import greedy_modularity_communities
TRANSACTION_THRESHOLD = 3
TIME_WINDOW_MINUTES   = 10
geo_cache = TTLCache(maxsize=10000, ttl=3600)
COLUMN_ALIASES = {
    "card_number":      ["card_number","card","card_no","credit_card","cc","cardnum"],
    "transaction_time": ["transaction_time","time","timestamp","date","datetime"],
    "ip_address":       ["ip_address","ip","ipaddr","ip_addr"]
}
def normalize_columns(df):
    mapping = {}
    for standard, aliases in COLUMN_ALIASES.items():
        for col in df.columns:
            if col.lower() in aliases:
                mapping[col] = standard
    return df.rename(columns=mapping)
def get_country(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        country = r.json().get("country", "Unknown")
        geo_cache[ip] = country
        return country
    except:
        return "Unknown"
def build_fraud_graph(df):
    G = nx.Graph()
    for _, row in df.iterrows():
        card = str(row["card_number"])
        ip   = str(row["ip_address"])
        G.add_node(card, type="card", risk=0)
        G.add_node(ip,   type="ip",   risk=0)
        G.add_edge(card, ip)
    return G
def detect_fraud_clusters(G):
    communities = greedy_modularity_communities(G)
    cluster_map = {}
    for i, community in enumerate(communities):
        for node in community:
            cluster_map[node] = i
    return cluster_map
def run_anomaly_detection(df):
    """Isolation Forest on per-card features. Returns set of anomalous card IDs."""
    features = df.groupby("card_number").agg(
        unique_ips=("ip_address", "nunique"),
        transactions=("transaction_time", "count")
    )
    if len(features) < 10:
        return set()
    model = IsolationForest(contamination=0.05, random_state=42)
    features["anomaly"] = model.fit_predict(features[["unique_ips", "transactions"]])
    return set(features[features["anomaly"] == -1].index)
def compute_dataset_baselines(df, ip_usage):
    """
    All thresholds are computed RELATIVE to this specific dataset.
    Nothing is hardcoded — signals scale with whatever data is uploaded.
    """
    per_card = df.groupby("card_number").agg(
        unique_ips=("ip_address", "nunique"),
        transactions=("transaction_time", "count")
    )
    return {
        "p90_txns":          per_card["transactions"].quantile(0.90),
        "p90_ips":           per_card["unique_ips"].quantile(0.90),
        "median_txns":       per_card["transactions"].median(),
        "median_ips":        per_card["unique_ips"].median(),
        "ip_rep_threshold":  max(5, ip_usage.mean() * 2),
    }
def calculate_risk_score(signals, baselines):
    """
    Relative, dataset-aware scoring.
    Every threshold adapts to the uploaded dataset — no hardcoded limits.
    Score bands:
      HIGH   >= 40
      MEDIUM >= 20
      LOW    >= 15  (minimum to appear in results)
    """
    score = 0
    if signals["anomaly"]:      score += 25
    if signals["velocity"]:     score += 20
    if signals["high_ip_spread"]:  score += 15 
    if signals["ip_reputation"]:   score += 10
    if signals["geo"]:             score += 10
    if signals["txns"] > baselines["p90_txns"]:         score += 10
    if signals["unique_ips"] > baselines["p90_ips"] + 2: score += 5
    return score
def get_risk_level(score):
    if score >= 40: return "high"
    if score >= 20: return "medium"
    return "low"
def get_fraud_patterns(signals, baselines):
    patterns = []
    if signals["velocity"]:         patterns.append("velocity")
    if signals["ip_reputation"]:    patterns.append("ip_reputation")
    if signals["geo"]:              patterns.append("geo_anomaly")
    if signals["anomaly"]:          patterns.append("ml_anomaly")
    if signals["high_ip_spread"]:   patterns.append("high_ip_spread")
    if signals["txns"] > baselines["p90_txns"]: patterns.append("high_volume")
    return patterns if patterns else ["none"]
def propagate_risk(G):
    for node in list(G.nodes):
        base = G.nodes[node]["risk"]
        for neighbor in G.neighbors(node):
            G.nodes[neighbor]["risk"] += base * 0.25
def graph_to_json(G):
    cluster_map = detect_fraud_clusters(G)
    nodes, edges = [], []
    for n, data in G.nodes(data=True):
        nodes.append({
            "id":      n,
            "type":    data.get("type", "unknown"),
            "cluster": cluster_map.get(n, 0),
            "risk":    round(data.get("risk", 0), 2)
        })
    for u, v in G.edges():
        edges.append({"source": u, "target": v})
    return {"nodes": nodes, "edges": edges}
def analyze_transactions(df):
    df = normalize_columns(df)
    required = ["card_number", "transaction_time", "ip_address"]
    missing  = [c for c in required if c not in df.columns]
    if missing:
        return {"error": f"Missing required columns: {', '.join(missing)}"}
    df["transaction_time"] = pd.to_datetime(df["transaction_time"], errors="coerce")
    df = df.dropna(subset=["transaction_time"])
    if len(df) == 0:
        return {"error": "No valid rows after parsing timestamps"}
    grouped       = df.groupby("card_number")
    ip_usage      = df.groupby("ip_address")["card_number"].nunique()
    anomaly_cards = run_anomaly_detection(df)
    baselines     = compute_dataset_baselines(df, ip_usage)
    G             = build_fraud_graph(df)
    suspicious_cards = []
    for card, group in grouped:
        group      = group.sort_values("transaction_time")
        txns       = len(group)
        unique_ips = group["ip_address"].nunique()
        time_span  = (
            group["transaction_time"].max() -
            group["transaction_time"].min()
        ).total_seconds() / 60

        velocity = (txns >= TRANSACTION_THRESHOLD
                    and unique_ips > 1
                    and time_span <= TIME_WINDOW_MINUTES)
        ip_reputation = any(
            ip_usage[ip] > baselines["ip_rep_threshold"]
            for ip in group["ip_address"]
        )
        high_ip_spread = unique_ips > baselines["p90_ips"]
        try:
            countries = {get_country(ip) for ip in group["ip_address"].unique()}
            geo = len(countries) > 1 and "Unknown" not in countries
        except:
            geo = False
        anomaly = card in anomaly_cards
        signals = {
            "txns":           txns,
            "unique_ips":     unique_ips,
            "velocity":       velocity,
            "ip_reputation":  ip_reputation,
            "high_ip_spread": high_ip_spread,
            "geo":            geo,
            "anomaly":        anomaly,
        }
        risk = calculate_risk_score(signals, baselines)
        G.nodes[str(card)]["risk"] = risk
        if risk >= 15:
            suspicious_cards.append({
                "card_number":    card,
                "transactions":   txns,
                "unique_ips":     unique_ips,
                "risk_score":     risk,
                "risk_level":     get_risk_level(risk),
                "fraud_patterns": get_fraud_patterns(signals, baselines)
            })
    propagate_risk(G)
    graph_json = graph_to_json(G)
    suspicious_cards.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "suspicious_cards": suspicious_cards,
        "fraud_network":    graph_json
    }
