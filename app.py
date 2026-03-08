from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from detector import analyze_transactions
app = Flask(__name__)
CORS(app)
@app.route("/")
def home():
    return jsonify({
        "message": "Card Fraud Detection API running"
    })
@app.route("/health")
def health():
    return jsonify({
        "status": "ok"
    })
@app.route("/docs")
def docs():
    api_docs = {
        "endpoint": "/analyze",
        "method": "POST",
        "input_format": {
            "file": "CSV upload",
            "required_columns": [
                "card_number",
                "transaction_time",
                "ip_address"
            ]
        },
        "description": "Detects suspicious card usage based on IP variation and transaction frequency."
    }
    return jsonify(api_docs)
@app.route("/summary")
def summary():
    data = {
        "system": "Card Fraud Detection",
        "detection_method": [
            "Transaction frequency threshold",
            "Multiple IP detection",
            "Short time window anomaly"
        ]
    }
    return jsonify(data)
@app.route("/test")
def test():
    sample_data = {
        "suspicious_cards": [
            {
                "card_number": "11112222",
                "transactions": 3,
                "unique_ips": 2,
                "time_span_minutes": 4,
                "risk_score": 16,
                "risk_level": "MEDIUM",
                "reason": "Multiple IP addresses used within short time window"
            }
        ]
    }
    return jsonify(sample_data)
@app.route("/analyze", methods=["POST"])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        filename = file.filename.lower()
        try:
            if filename.endswith(".csv"):
                df = pd.read_csv(file)
            elif filename.endswith(".xlsx") or filename.endswith(".xls"):
                df = pd.read_excel(file)
            elif filename.endswith(".json"):
                df = pd.read_json(file)
            else:
                return jsonify({"error": "Unsupported file format"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    result = analyze_transactions(df)
    total_cards = df["card_number"].nunique()
    return jsonify({
        "total_cards_analyzed": int(total_cards),
        "suspicious_cards": result
    })
if __name__ == "__main__":
    app.run(debug=True)
