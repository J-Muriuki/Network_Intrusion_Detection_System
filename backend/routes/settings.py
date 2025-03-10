import json
from flask import Blueprint, request, jsonify

settings_bp = Blueprint("settings", __name__)

SETTINGS_FILE = "C:/Users/EFAC/PycharmProjects/NIDS/logs/settings.json"

# Load settings
def load_settings():
    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"captureLimit": 100, "alertThreshold": 8}

# Save settings
def save_settings(data):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=4)

# API to get settings
@settings_bp.route("settings", methods=["GET"])
def get_settings():
    return jsonify(load_settings())

# API to update settings
@settings_bp.route("settings", methods=["POST"])
def update_settings():
    new_settings = request.json
    save_settings(new_settings)
    return jsonify({"message": "Settings updated successfully"})





