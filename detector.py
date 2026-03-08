import pandas as pd
import networkx as nx
import requests
from sklearn.ensemble import IsolationForest
from cachetools import TTLCache
from networkx.algorithms.community import greedy_modularity_communities
TRANSACTION_THRESHOLD = 3
TIME_WINDOW_MINUTES = 10
geo_cache = TTLCache(maxsize=10000, ttl=3600)
COLUMN_ALIASES = {
    "card_number": ["card_number","card","card_no","credit_card","cc","cardnum"],
    "transaction_time": ["transaction_time","time","timestamp","date","datetime"],
    "ip_address": ["ip_address","ip","ipaddr","ip_addr"]
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
        country = r.json().get("country","Unknown")
        geo_cache[ip] = country
        return country
    except:
        return "Unknown"
def build_fraud_graph(df):
    G = nx.Graph()
    for _,row in df.iterrows():
        card = str(row["card_number"])
        ip = str(row["ip_address"])
        G.add_node(card,type="card",risk=0)
        G.add_node(ip,type="ip",risk=0)
        G.add_edge(card,ip)
    return G
def detect_fraud_clusters(G):
    communities = greedy_modularity_communities(G)
    cluster_map = {}
    for i,community in enumerate(communities):
        for node in community:
            cluster_map[node] = i
    return cluster_map
def run_anomaly_detection(df):
    features = df.groupby("card_number").agg({
        "ip_address":"nunique",
        "transaction_time":"count"
    }).rename(columns={
        "ip_address":"unique_ips",
        "transaction_time":"transactions"
    })
    model = IsolationForest(contamination=0.05,random_state=42)
    features["anomaly"] = model.fit_predict(features)
    anomalies = features[features["anomaly"] == -1]
    return anomalies.index.tolist()
def calculate_base_risk(signals):
    score = 0
    score += signals["transactions"] * 2
    score += signals["unique_ips"] * 4
    if signals["velocity"]:
        score += 10
    if signals["ip_reputation"]:
        score += 8
    if signals["geo"]:
        score += 10
    if signals["anomaly"]:
        score += 12
    return score
def propagate_risk(G):
    for node in G.nodes:
        base = G.nodes[node]["risk"]
        for neighbor in G.neighbors(node):
            G.nodes[neighbor]["risk"] += base * 0.25
def graph_to_json(G):
    cluster_map = detect_fraud_clusters(G)
    nodes = []
    edges = []
    for n,data in G.nodes(data=True):
        nodes.append({
            "id":n,
            "type":data.get("type","unknown"),
            "cluster":cluster_map.get(n,0),
            "risk":data.get("risk",0)
        })
    for u,v in G.edges():
        edges.append({
            "source":u,
            "target":v
        })
    return {
        "nodes":nodes,
        "edges":edges
    }
def analyze_transactions(df):
    df = normalize_columns(df)
    required = ["card_number","transaction_time","ip_address"]
    if not all(c in df.columns for c in required):
        return {"error":"Missing required columns"}
    df["transaction_time"] = pd.to_datetime(df["transaction_time"])
    grouped = df.groupby("card_number")
    ip_usage = df.groupby("ip_address")["card_number"].nunique()
    anomaly_cards = run_anomaly_detection(df)
    G = build_fraud_graph(df)
    suspicious_cards = []
    for card,group in grouped:
        group = group.sort_values("transaction_time")
        transactions = len(group)
        unique_ips = group["ip_address"].nunique()
        time_span = (
            group["transaction_time"].max() -
            group["transaction_time"].min()
        ).total_seconds()/60
        velocity = transactions >= TRANSACTION_THRESHOLD and unique_ips > 1 and time_span <= TIME_WINDOW_MINUTES
        ip_reputation = any(ip_usage[ip] > 5 for ip in group["ip_address"])
        geo = len({get_country(ip) for ip in group["ip_address"]}) > 1
        anomaly = card in anomaly_cards
        signals = {
            "transactions":transactions,
            "unique_ips":unique_ips,
            "velocity":velocity,
            "ip_reputation":ip_reputation,
            "geo":geo,
            "anomaly":anomaly
        }
        risk = calculate_base_risk(signals)
        G.nodes[str(card)]["risk"] = risk
        if risk >= 15:
            suspicious_cards.append({
                "card_number":card,
                "transactions":transactions,
                "unique_ips":unique_ips,
                "risk_score":risk
            })
    propagate_risk(G)
    graph_json = graph_to_json(G)
    return {
        "suspicious_cards":suspicious_cards,
        "fraud_network":graph_json
    }
