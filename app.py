from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from detector import analyze_transactions, normalize_columns
app = Flask(__name__)
CORS(app)
MAX_ROWS = 500000
@app.route("/")
def home():
    return jsonify({
        "message": "Card Fraud Detection API running"
    })
@app.route("/health")
def health():
    return jsonify({"status": "ok"})
@app.route("/docs")
def docs():
    return jsonify({
        "endpoint": "/analyze",
        "method": "POST",
        "supported_formats": ["csv", "xlsx", "json"],
        "required_fields": [
            "card_number",
            "transaction_time",
            "ip_address"
        ]
    })
@app.route("/detect_schema", methods=["POST"])
def detect_schema():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    df = pd.read_csv(file)
    detected = {}
    for col in df.columns:
        name = col.lower()
        if "card" in name:
            detected["card_number"] = col
        if "ip" in name:
            detected["ip_address"] = col
        if "time" in name or "date" in name:
            detected["transaction_time"] = col
    return jsonify({
        "detected_schema": detected,
        "columns": list(df.columns)
    })
@app.route("/dataset_info", methods=["POST"])
def dataset_info():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    df = pd.read_csv(file)
    info = {
        "rows": len(df),
        "columns": list(df.columns)
    }
    return jsonify(info)
@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
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
    df = normalize_columns(df)
    rows_original = len(df)
    if len(df) > MAX_ROWS:
        df = df.sample(MAX_ROWS)
    result = analyze_transactions(df)
    return jsonify({
        "rows_original": rows_original,
        "rows_processed": len(df),
        "total_cards_analyzed": int(df["card_number"].nunique()),
        "suspicious_cards": result
    })


if __name__ == "__main__":
    app.run(debug=True)
