# backend/routes/auth.py
from flask import Blueprint, request, jsonify
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from backend.db import db, cursor
# We do NOT import app here. Instead, we have everything needed from db or other modules.

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password).decode("utf-8")

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, hashed_password, role)
        )
        db.commit()
        return jsonify({"message": "User created successfully"}), 201
    except:
        db.rollback()
        return jsonify({"error": "Username already exists"}), 400

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()  # user is a tuple e.g. (id, username, password_hash, role)

    if user:
        user_id, user_name, user_hash, user_role = user
        # user_hash is the hashed password in DB
        if check_password_hash(user_hash, password):
            # Create JWT with user info
            access_token = create_access_token(identity={"id": user_id, "role": user_role})
            return jsonify({"token": access_token, "role": user_role}), 200

    return jsonify({"error": "Invalid credentials"}), 401
