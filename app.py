from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from detector import analyze_transactions
app = Flask(__name__)
CORS(app)
MAX_ROWS = 10000
system_metrics = {
    "datasets_processed": 0,
    "transactions_processed": 0
}
def load_and_sample(file):
    """
    Read CSV and apply card-preserving proportional sampling
    if row count exceeds MAX_ROWS. Every card in the dataset
    keeps at least 1 row so no card is completely dropped.
    """
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()
    original_rows = len(df)

    if original_rows > MAX_ROWS:
        frac = MAX_ROWS / original_rows
        cols = df.columns.tolist()
        df = (df.groupby('card_number')[cols]
                .apply(lambda x: x.sample(max(1, round(len(x) * frac)), random_state=42))
                .reset_index(drop=True))
    df._original_row_count = original_rows
    return df, original_rows
@app.route("/")
def home():
    return jsonify({
        "system": "Fraud Detection Engine",
        "status": "running",
        "row_limit": MAX_ROWS
    })
@app.route("/metrics")
def metrics():
    return jsonify(system_metrics)
@app.route("/dashboard")
def dashboard():
    return jsonify({
        "system_status": "active",
        "datasets_processed": system_metrics["datasets_processed"],
        "transactions_processed": system_metrics["transactions_processed"],
        "row_limit": MAX_ROWS
    })
@app.route("/detect_schema", methods=["POST"])
def detect_schema():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        df = pd.read_csv(request.files["file"])
        df.columns = df.columns.str.strip()
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    schema = {col: str(dtype) for col, dtype in df.dtypes.items()}
    return jsonify({
        "columns": schema,
        "row_count": len(df),
        "sampled": len(df) > MAX_ROWS,
        "row_limit": MAX_ROWS
    })
@app.route("/dataset_info", methods=["POST"])
def dataset_info():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        df = pd.read_csv(request.files["file"])
        df.columns = df.columns.str.strip()
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "row_count": len(df),
        "column_count": len(df.columns),
        "columns": list(df.columns),
        "missing_values": df.isnull().sum().to_dict(),
        "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
        "sampled": len(df) > MAX_ROWS,
        "row_limit": MAX_ROWS
    })
@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        df, original_rows = load_and_sample(request.files["file"])
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    result = analyze_transactions(df)
    if "error" not in result:
        system_metrics["datasets_processed"] += 1
        system_metrics["transactions_processed"] += original_rows
        result["sampled"] = original_rows > MAX_ROWS
        result["original_rows"] = original_rows
        result["analyzed_rows"] = len(df)
    return jsonify(result)
@app.route("/fraud_network", methods=["POST"])
def fraud_network():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        df, original_rows = load_and_sample(request.files["file"])
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    result = analyze_transactions(df)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result["fraud_network"])
if __name__ == "__main__":
    app.run()
