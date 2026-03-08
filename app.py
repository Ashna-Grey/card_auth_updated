from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from detector import analyze_transactions
app = Flask(__name__)
CORS(app)
system_metrics = {
    "datasets_processed":0,
    "transactions_processed":0
}
@app.route("/")
def home():
    return jsonify({"system":"Fraud Detection Engine"})
@app.route("/metrics")
def metrics():
    return jsonify(system_metrics)
@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error":"No file uploaded"}),400
    file = request.files["file"]
    df = pd.read_csv(file)
    result = analyze_transactions(df)
    system_metrics["datasets_processed"] += 1
    system_metrics["transactions_processed"] += len(df)
    return jsonify(result)
@app.route("/dashboard")
def dashboard():
    return jsonify({
        "system_status":"active",
        "datasets_processed":system_metrics["datasets_processed"],
        "transactions_processed":system_metrics["transactions_processed"]
    })
if __name__ == "__main__":
    app.run()
