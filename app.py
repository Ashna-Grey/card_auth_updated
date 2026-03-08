from flask import Flask, request, jsonify
from detector import analyze_transactions
import pandas as pd
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
@app.route("/")
def home():
    return jsonify({"message": "Fraud IP Detection API running"})
@app.route("/test")
def test():
    sample_data = {
        "suspicious_cards": [
            {
                "card_number": "11112222",
                "transactions": 3,
                "unique_ips": 2
            }
        ]
    }
    return jsonify(sample_data)
@app.route("/analyze", methods=["POST"])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    try:
        df = pd.read_csv(file)
    except Exception as e:
        return jsonify({"error": "Invalid CSV"}), 400
    result = analyze_transactions(df)
    return jsonify({
        "suspicious_cards": result
    })
if __name__ == "__main__":
    app.run(debug=True)
