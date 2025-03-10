import os
from flask import Blueprint, jsonify
import pandas as pd

logs_bp = Blueprint("logs", __name__)


@logs_bp.route('/logs', methods=['GET'])

def get_logs():
    logs_path = "C:/Users/EFAC/PycharmProjects/NIDS/logs/traffic_log.csv"

    if not os.path.exists(logs_path):
        print("ERROR: traffic_log.csv not found!")
        return jsonify({"error": "No logs found"}), 404

    try:
        df = pd.read_csv(logs_path, on_bad_lines="skip")  # Skip bad rows
        df = df.dropna()  # Remove any remaining null rows
        print(df.head())  # Debugging: Print first few rows
        return jsonify(df.to_dict(orient="records"))
    except Exception as e:
        print(f"ERROR: Failed to read CSV - {e}")
        return jsonify({"error": "Failed to process logs"}), 500
