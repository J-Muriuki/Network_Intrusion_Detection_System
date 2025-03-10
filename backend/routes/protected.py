from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

protected_bp = Blueprint("protected", __name__)

@protected_bp.route("/admin-only", methods=["GET"])
@jwt_required()
def admin_only():
    user = get_jwt_identity()
    if user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify({"message": "Welcome Admin!"}), 200

@protected_bp.route("/user-data", methods=["GET"])
@jwt_required()
def user_data():
    user = get_jwt_identity()
    return jsonify({"message": f"Hello {user['id']}, you are a {user['role']}!"}), 200
